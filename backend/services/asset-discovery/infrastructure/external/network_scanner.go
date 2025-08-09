package external

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"asset-discovery/domain/entity"
	"asset-discovery/domain/service"
)

// NetworkScanner implements the NetworkScannerService interface
type NetworkScanner struct {
	logger           *zap.Logger
	maxConcurrency   int
	defaultTimeout   time.Duration
	nmapPath         string
	enableNmap       bool
}

// NewNetworkScanner creates a new network scanner
func NewNetworkScanner(logger *zap.Logger) *NetworkScanner {
	scanner := &NetworkScanner{
		logger:         logger,
		maxConcurrency: 100,
		defaultTimeout: 30 * time.Second,
		nmapPath:       "/usr/bin/nmap",
		enableNmap:     true,
	}

	// Check if nmap is available
	if _, err := exec.LookPath("nmap"); err != nil {
		scanner.enableNmap = false
		logger.Warn("nmap not found, some scanning features will be limited")
	}

	return scanner
}

// PingScan performs a ping scan on the provided targets
func (ns *NetworkScanner) PingScan(ctx context.Context, targets []string, options service.ScanOptions) ([]*entity.Asset, error) {
	ns.logger.Info("Starting ping scan", zap.Int("targets", len(targets)))

	var assets []*entity.Asset
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Create semaphore for concurrency control
	sem := make(chan struct{}, ns.maxConcurrency)
	if options.MaxConcurrency > 0 && options.MaxConcurrency < ns.maxConcurrency {
		sem = make(chan struct{}, options.MaxConcurrency)
	}

	timeout := ns.defaultTimeout
	if options.Timeout > 0 {
		timeout = options.Timeout
	}

	for _, target := range targets {
		wg.Add(1)
		go func(target string) {
			defer wg.Done()
			
			// Acquire semaphore
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()

			// Create context with timeout for this specific ping
			pingCtx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()

			if alive := ns.pingHost(pingCtx, target); alive {
				asset := ns.createBasicAsset(target, entity.AssetTypeUnknown)
				asset.DiscoveryMethod = "ping"
				asset.Status = entity.AssetStatusActive
				
				// Try to resolve hostname if target is an IP
				if ip := net.ParseIP(target); ip != nil {
					if hostnames, err := net.LookupAddr(target); err == nil && len(hostnames) > 0 {
						asset.NetworkInfo.Hostname = strings.TrimSuffix(hostnames[0], ".")
						asset.NetworkInfo.FQDN = hostnames[0]
					}
				}

				mu.Lock()
				assets = append(assets, asset)
				mu.Unlock()

				ns.logger.Debug("Host is alive", zap.String("target", target))
			}
		}(target)
	}

	wg.Wait()

	ns.logger.Info("Ping scan completed", 
		zap.Int("targets_scanned", len(targets)), 
		zap.Int("hosts_found", len(assets)))

	return assets, nil
}

// PortScan performs a port scan on the provided targets
func (ns *NetworkScanner) PortScan(ctx context.Context, targets []string, options service.ScanOptions) ([]*entity.Asset, error) {
	ns.logger.Info("Starting port scan", zap.Int("targets", len(targets)))

	var assets []*entity.Asset
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Parse port ranges
	ports, err := ns.parsePortRanges(options.PortRanges)
	if err != nil {
		return nil, fmt.Errorf("invalid port ranges: %w", err)
	}

	// Default ports if none specified
	if len(ports) == 0 {
		ports = []int{21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995, 1723, 3306, 3389, 5432, 5900, 8080}
	}

	// Create semaphore for concurrency control
	sem := make(chan struct{}, ns.maxConcurrency)
	if options.MaxConcurrency > 0 && options.MaxConcurrency < ns.maxConcurrency {
		sem = make(chan struct{}, options.MaxConcurrency)
	}

	for _, target := range targets {
		wg.Add(1)
		go func(target string) {
			defer wg.Done()
			
			// Acquire semaphore
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()

			asset := ns.scanPortsOnHost(ctx, target, ports, options)
			if asset != nil {
				mu.Lock()
				assets = append(assets, asset)
				mu.Unlock()
			}
		}(target)
	}

	wg.Wait()

	ns.logger.Info("Port scan completed", 
		zap.Int("targets_scanned", len(targets)), 
		zap.Int("hosts_found", len(assets)))

	return assets, nil
}

// ServiceScan performs service detection on the provided targets
func (ns *NetworkScanner) ServiceScan(ctx context.Context, targets []string, options service.ScanOptions) ([]*entity.Asset, error) {
	ns.logger.Info("Starting service scan", zap.Int("targets", len(targets)))

	// If nmap is available, use it for service detection
	if ns.enableNmap {
		return ns.nmapServiceScan(ctx, targets, options)
	}

	// Fallback to basic port scanning with service guessing
	assets, err := ns.PortScan(ctx, targets, options)
	if err != nil {
		return nil, err
	}

	// Enhance with basic service detection
	for _, asset := range assets {
		if asset.NetworkInfo != nil {
			for i := range asset.NetworkInfo.OpenPorts {
				port := &asset.NetworkInfo.OpenPorts[i]
				if port.Service == "" {
					port.Service = ns.guessServiceFromPort(port.Number)
				}
			}
		}
	}

	return assets, nil
}

// OSDetection performs OS detection on the provided targets
func (ns *NetworkScanner) OSDetection(ctx context.Context, targets []string, options service.ScanOptions) ([]*entity.Asset, error) {
	ns.logger.Info("Starting OS detection", zap.Int("targets", len(targets)))

	if !ns.enableNmap {
		ns.logger.Warn("nmap not available, OS detection limited")
		return ns.ServiceScan(ctx, targets, options)
	}

	return ns.nmapOSDetection(ctx, targets, options)
}

// ComprehensiveScan performs a comprehensive scan including all techniques
func (ns *NetworkScanner) ComprehensiveScan(ctx context.Context, targets []string, options service.ScanOptions) ([]*entity.Asset, error) {
	ns.logger.Info("Starting comprehensive scan", zap.Int("targets", len(targets)))

	var allAssets []*entity.Asset
	assetMap := make(map[string]*entity.Asset) // IP -> Asset mapping
	var mu sync.Mutex

	// Phase 1: Ping scan to find live hosts
	ns.logger.Debug("Phase 1: Ping scan")
	liveAssets, err := ns.PingScan(ctx, targets, options)
	if err != nil {
		ns.logger.Error("Ping scan failed", zap.Error(err))
	} else {
		for _, asset := range liveAssets {
			if asset.NetworkInfo != nil && asset.NetworkInfo.IPAddress != "" {
				mu.Lock()
				assetMap[asset.NetworkInfo.IPAddress] = asset
				mu.Unlock()
			}
		}
	}

	// Extract live targets
	var liveTargets []string
	mu.Lock()
	for ip := range assetMap {
		liveTargets = append(liveTargets, ip)
	}
	mu.Unlock()

	if len(liveTargets) == 0 {
		ns.logger.Info("No live hosts found")
		return allAssets, nil
	}

	// Phase 2: Port scanning on live hosts
	ns.logger.Debug("Phase 2: Port scanning", zap.Int("live_hosts", len(liveTargets)))
	portAssets, err := ns.PortScan(ctx, liveTargets, options)
	if err != nil {
		ns.logger.Error("Port scan failed", zap.Error(err))
	} else {
		// Merge port information
		for _, portAsset := range portAssets {
			if portAsset.NetworkInfo != nil && portAsset.NetworkInfo.IPAddress != "" {
				mu.Lock()
				if existing, exists := assetMap[portAsset.NetworkInfo.IPAddress]; exists {
					ns.mergeAssetInfo(existing, portAsset)
				} else {
					assetMap[portAsset.NetworkInfo.IPAddress] = portAsset
				}
				mu.Unlock()
			}
		}
	}

	// Phase 3: Service detection (if enabled)
	if options.ServiceDetection {
		ns.logger.Debug("Phase 3: Service detection")
		serviceAssets, err := ns.ServiceScan(ctx, liveTargets, options)
		if err != nil {
			ns.logger.Error("Service scan failed", zap.Error(err))
		} else {
			// Merge service information
			for _, serviceAsset := range serviceAssets {
				if serviceAsset.NetworkInfo != nil && serviceAsset.NetworkInfo.IPAddress != "" {
					mu.Lock()
					if existing, exists := assetMap[serviceAsset.NetworkInfo.IPAddress]; exists {
						ns.mergeAssetInfo(existing, serviceAsset)
					} else {
						assetMap[serviceAsset.NetworkInfo.IPAddress] = serviceAsset
					}
					mu.Unlock()
				}
			}
		}
	}

	// Phase 4: OS detection (if enabled)
	if options.OSDetection {
		ns.logger.Debug("Phase 4: OS detection")
		osAssets, err := ns.OSDetection(ctx, liveTargets, options)
		if err != nil {
			ns.logger.Error("OS detection failed", zap.Error(err))
		} else {
			// Merge OS information
			for _, osAsset := range osAssets {
				if osAsset.NetworkInfo != nil && osAsset.NetworkInfo.IPAddress != "" {
					mu.Lock()
					if existing, exists := assetMap[osAsset.NetworkInfo.IPAddress]; exists {
						ns.mergeAssetInfo(existing, osAsset)
					} else {
						assetMap[osAsset.NetworkInfo.IPAddress] = osAsset
					}
					mu.Unlock()
				}
			}
		}
	}

	// Convert map to slice
	mu.Lock()
	for _, asset := range assetMap {
		allAssets = append(allAssets, asset)
	}
	mu.Unlock()

	ns.logger.Info("Comprehensive scan completed", 
		zap.Int("targets_scanned", len(targets)), 
		zap.Int("assets_found", len(allAssets)))

	return allAssets, nil
}

// ValidateTargets validates the accessibility of targets
func (ns *NetworkScanner) ValidateTargets(ctx context.Context, targets []string) ([]string, []string, error) {
	var valid, invalid []string
	var mu sync.Mutex
	var wg sync.WaitGroup

	sem := make(chan struct{}, ns.maxConcurrency)

	for _, target := range targets {
		wg.Add(1)
		go func(target string) {
			defer wg.Done()
			
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()

			if ns.validateTarget(target) {
				mu.Lock()
				valid = append(valid, target)
				mu.Unlock()
			} else {
				mu.Lock()
				invalid = append(invalid, target)
				mu.Unlock()
			}
		}(target)
	}

	wg.Wait()

	ns.logger.Debug("Target validation completed", 
		zap.Int("valid", len(valid)), 
		zap.Int("invalid", len(invalid)))

	return valid, invalid, nil
}

// Helper methods

func (ns *NetworkScanner) pingHost(ctx context.Context, host string) bool {
	// Use Go's built-in net package for basic connectivity check
	timeout := time.Second * 3
	if deadline, ok := ctx.Deadline(); ok {
		timeout = time.Until(deadline)
	}

	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, "80"), timeout)
	if err == nil {
		conn.Close()
		return true
	}

	// Try ICMP ping if available
	if ns.enableNmap {
		return ns.icmpPing(ctx, host)
	}

	// Try common ports as fallback
	commonPorts := []string{"22", "23", "25", "53", "80", "135", "139", "443", "445"}
	for _, port := range commonPorts {
		select {
		case <-ctx.Done():
			return false
		default:
		}

		conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), time.Second)
		if err == nil {
			conn.Close()
			return true
		}
	}

	return false
}

func (ns *NetworkScanner) icmpPing(ctx context.Context, host string) bool {
	if !ns.enableNmap {
		return false
	}

	// Use ping command
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "ping", "-c", "1", "-W", "3", host)
	err := cmd.Run()
	return err == nil
}

func (ns *NetworkScanner) scanPortsOnHost(ctx context.Context, host string, ports []int, options service.ScanOptions) *entity.Asset {
	var openPorts []entity.Port
	var wg sync.WaitGroup

	timeout := 3 * time.Second
	if options.Timeout > 0 {
		timeout = options.Timeout / time.Duration(len(ports))
		if timeout < time.Second {
			timeout = time.Second
		}
	}

	portChan := make(chan entity.Port, len(ports))
	sem := make(chan struct{}, 50) // Limit concurrent port scans

	for _, port := range ports {
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()

			if ns.isPortOpen(ctx, host, port, timeout) {
				portInfo := entity.Port{
					Number:   port,
					Protocol: "tcp",
					Service:  ns.guessServiceFromPort(port),
					State:    "open",
				}

				// Try to grab banner if service detection is enabled
				if options.ServiceDetection {
					if banner, version := ns.grabBanner(ctx, host, port); banner != "" {
						portInfo.Banner = banner
						portInfo.Version = version
					}
				}

				select {
				case portChan <- portInfo:
				case <-ctx.Done():
				}
			}
		}(port)
	}

	wg.Wait()
	close(portChan)

	// Collect open ports
	for port := range portChan {
		openPorts = append(openPorts, port)
	}

	if len(openPorts) == 0 {
		return nil
	}

	asset := ns.createBasicAsset(host, ns.classifyAssetByPorts(openPorts))
	asset.DiscoveryMethod = "port_scan"
	asset.NetworkInfo.OpenPorts = openPorts
	asset.Status = entity.AssetStatusActive

	return asset
}

func (ns *NetworkScanner) isPortOpen(ctx context.Context, host string, port int, timeout time.Duration) bool {
	address := net.JoinHostPort(host, strconv.Itoa(port))
	
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func (ns *NetworkScanner) grabBanner(ctx context.Context, host string, port int) (string, string) {
	address := net.JoinHostPort(host, strconv.Itoa(port))
	
	conn, err := net.DialTimeout("tcp", address, 3*time.Second)
	if err != nil {
		return "", ""
	}
	defer conn.Close()

	// Set read timeout
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))

	// Try to read banner
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		// Some services require a probe
		switch port {
		case 80, 8080:
			conn.Write([]byte("GET / HTTP/1.0\r\n\r\n"))
		case 22:
			// SSH banner is usually sent immediately
		case 25:
			// SMTP
			conn.Write([]byte("HELO test\r\n"))
		case 21:
			// FTP banner is usually sent immediately
		default:
			conn.Write([]byte("\r\n"))
		}
		
		n, err = conn.Read(buffer)
		if err != nil {
			return "", ""
		}
	}

	banner := strings.TrimSpace(string(buffer[:n]))
	version := ns.extractVersionFromBanner(banner)
	
	return banner, version
}

func (ns *NetworkScanner) extractVersionFromBanner(banner string) string {
	// Simple version extraction patterns
	banner = strings.ToLower(banner)
	
	// Common version patterns
	patterns := []string{
		`(\d+\.\d+\.\d+)`,
		`(\d+\.\d+)`,
		`version (\d+\.\d+\.\d+)`,
		`v(\d+\.\d+\.\d+)`,
	}

	for _, pattern := range patterns {
		// Simple string matching instead of regex for this example
		if strings.Contains(banner, "version") {
			parts := strings.Split(banner, "version")
			if len(parts) > 1 {
				versionPart := strings.TrimSpace(parts[1])
				if len(versionPart) > 0 {
					fields := strings.Fields(versionPart)
					if len(fields) > 0 {
						return fields[0]
					}
				}
			}
		}
	}

	return ""
}

func (ns *NetworkScanner) guessServiceFromPort(port int) string {
	serviceMap := map[int]string{
		21:   "ftp",
		22:   "ssh",
		23:   "telnet",
		25:   "smtp",
		53:   "dns",
		80:   "http",
		110:  "pop3",
		111:  "rpcbind",
		135:  "rpc",
		139:  "netbios-ssn",
		143:  "imap",
		443:  "https",
		445:  "smb",
		993:  "imaps",
		995:  "pop3s",
		1723: "pptp",
		3306: "mysql",
		3389: "rdp",
		5432: "postgresql",
		5900: "vnc",
		8080: "http-alt",
		8443: "https-alt",
	}

	if service, exists := serviceMap[port]; exists {
		return service
	}

	return "unknown"
}

func (ns *NetworkScanner) classifyAssetByPorts(ports []entity.Port) entity.AssetType {
	// Classify asset type based on open ports
	hasWeb := false
	hasDB := false
	hasRDP := false
	hasSSH := false

	for _, port := range ports {
		switch port.Number {
		case 80, 443, 8080, 8443:
			hasWeb = true
		case 3306, 3389, 5432, 1433:
			hasDB = true
		case 3389:
			hasRDP = true
		case 22:
			hasSSH = true
		}
	}

	if hasDB {
		return entity.AssetTypeDatabase
	}
	if hasWeb {
		return entity.AssetTypeServer
	}
	if hasRDP || hasSSH {
		return entity.AssetTypeServer
	}

	return entity.AssetTypeEndpoint
}

func (ns *NetworkScanner) createBasicAsset(target string, assetType entity.AssetType) *entity.Asset {
	asset := entity.NewAsset(uuid.New(), target, assetType) // This will need proper tenant ID
	
	// Initialize network info
	networkInfo := &entity.NetworkInfo{}
	
	// Determine if target is IP or hostname
	if ip := net.ParseIP(target); ip != nil {
		networkInfo.IPAddress = target
		if ip.To4() != nil {
			networkInfo.IPVersion = "ipv4"
		} else {
			networkInfo.IPVersion = "ipv6"
		}
		
		// Try reverse DNS lookup
		if hostnames, err := net.LookupAddr(target); err == nil && len(hostnames) > 0 {
			networkInfo.Hostname = strings.TrimSuffix(hostnames[0], ".")
			networkInfo.FQDN = hostnames[0]
		}
	} else {
		networkInfo.Hostname = target
		networkInfo.FQDN = target
		
		// Try forward DNS lookup
		if ips, err := net.LookupIP(target); err == nil && len(ips) > 0 {
			networkInfo.IPAddress = ips[0].String()
			if ips[0].To4() != nil {
				networkInfo.IPVersion = "ipv4"
			} else {
				networkInfo.IPVersion = "ipv6"
			}
		}
	}

	asset.NetworkInfo = networkInfo
	asset.DiscoverySource = "network_scanner"
	asset.UpdateFingerprint()

	return asset
}

func (ns *NetworkScanner) mergeAssetInfo(existing, new *entity.Asset) {
	// Merge network information
	if new.NetworkInfo != nil {
		if existing.NetworkInfo == nil {
			existing.NetworkInfo = new.NetworkInfo
		} else {
			// Merge port information
			if len(new.NetworkInfo.OpenPorts) > 0 {
				portMap := make(map[int]entity.Port)
				
				// Add existing ports
				for _, port := range existing.NetworkInfo.OpenPorts {
					portMap[port.Number] = port
				}
				
				// Add new ports (or update existing with more info)
				for _, port := range new.NetworkInfo.OpenPorts {
					if existingPort, exists := portMap[port.Number]; exists {
						// Keep the one with more information
						if port.Service != "" && existingPort.Service == "" {
							existingPort.Service = port.Service
						}
						if port.Version != "" && existingPort.Version == "" {
							existingPort.Version = port.Version
						}
						if port.Banner != "" && existingPort.Banner == "" {
							existingPort.Banner = port.Banner
						}
						portMap[port.Number] = existingPort
					} else {
						portMap[port.Number] = port
					}
				}
				
				// Convert back to slice
				existing.NetworkInfo.OpenPorts = make([]entity.Port, 0, len(portMap))
				for _, port := range portMap {
					existing.NetworkInfo.OpenPorts = append(existing.NetworkInfo.OpenPorts, port)
				}
			}
			
			// Merge other network info
			if new.NetworkInfo.Hostname != "" && existing.NetworkInfo.Hostname == "" {
				existing.NetworkInfo.Hostname = new.NetworkInfo.Hostname
			}
			if new.NetworkInfo.FQDN != "" && existing.NetworkInfo.FQDN == "" {
				existing.NetworkInfo.FQDN = new.NetworkInfo.FQDN
			}
		}
	}

	// Merge system information
	if new.SystemInfo != nil {
		if existing.SystemInfo == nil {
			existing.SystemInfo = new.SystemInfo
		} else {
			// Merge OS information
			if new.SystemInfo.OperatingSystem != "" && existing.SystemInfo.OperatingSystem == "" {
				existing.SystemInfo.OperatingSystem = new.SystemInfo.OperatingSystem
			}
			if new.SystemInfo.OSVersion != "" && existing.SystemInfo.OSVersion == "" {
				existing.SystemInfo.OSVersion = new.SystemInfo.OSVersion
			}
		}
	}

	// Update timestamps
	existing.LastSeen = time.Now()
	existing.LastUpdated = time.Now()
	existing.UpdateFingerprint()
}

func (ns *NetworkScanner) validateTarget(target string) bool {
	// Check if it's a valid IP
	if ip := net.ParseIP(target); ip != nil {
		return true
	}

	// Check if it's a valid hostname
	if _, err := net.LookupHost(target); err == nil {
		return true
	}

	return false
}

func (ns *NetworkScanner) parsePortRanges(portRanges []string) ([]int, error) {
	var ports []int
	portSet := make(map[int]bool)

	for _, portRange := range portRanges {
		if strings.Contains(portRange, "-") {
			// Handle range (e.g., "1-1000")
			parts := strings.Split(portRange, "-")
			if len(parts) != 2 {
				return nil, fmt.Errorf("invalid port range: %s", portRange)
			}

			start, err := strconv.Atoi(strings.TrimSpace(parts[0]))
			if err != nil {
				return nil, fmt.Errorf("invalid start port in range %s: %w", portRange, err)
			}

			end, err := strconv.Atoi(strings.TrimSpace(parts[1]))
			if err != nil {
				return nil, fmt.Errorf("invalid end port in range %s: %w", portRange, err)
			}

			if start < 1 || end > 65535 || start > end {
				return nil, fmt.Errorf("invalid port range: %s", portRange)
			}

			for port := start; port <= end; port++ {
				if !portSet[port] {
					ports = append(ports, port)
					portSet[port] = true
				}
			}
		} else if strings.Contains(portRange, ",") {
			// Handle comma-separated list (e.g., "80,443,8080")
			portList := strings.Split(portRange, ",")
			for _, portStr := range portList {
				port, err := strconv.Atoi(strings.TrimSpace(portStr))
				if err != nil {
					return nil, fmt.Errorf("invalid port: %s", portStr)
				}
				if port < 1 || port > 65535 {
					return nil, fmt.Errorf("port out of range: %d", port)
				}
				if !portSet[port] {
					ports = append(ports, port)
					portSet[port] = true
				}
			}
		} else {
			// Handle single port
			port, err := strconv.Atoi(strings.TrimSpace(portRange))
			if err != nil {
				return nil, fmt.Errorf("invalid port: %s", portRange)
			}
			if port < 1 || port > 65535 {
				return nil, fmt.Errorf("port out of range: %d", port)
			}
			if !portSet[port] {
				ports = append(ports, port)
				portSet[port] = true
			}
		}
	}

	return ports, nil
}

// nmap-based implementations (require nmap to be installed)

func (ns *NetworkScanner) nmapServiceScan(ctx context.Context, targets []string, options service.ScanOptions) ([]*entity.Asset, error) {
	if !ns.enableNmap {
		return nil, fmt.Errorf("nmap not available")
	}

	// Build nmap command for service detection
	args := []string{"-sV", "-T4"}
	
	// Add port specification
	if len(options.PortRanges) > 0 {
		args = append(args, "-p", strings.Join(options.PortRanges, ","))
	}

	// Add targets
	args = append(args, targets...)

	// Execute nmap
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, "nmap", args...)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("nmap service scan failed: %w", err)
	}

	// Parse nmap output (simplified)
	return ns.parseNmapOutput(string(output))
}

func (ns *NetworkScanner) nmapOSDetection(ctx context.Context, targets []string, options service.ScanOptions) ([]*entity.Asset, error) {
	if !ns.enableNmap {
		return nil, fmt.Errorf("nmap not available")
	}

	// Build nmap command for OS detection
	args := []string{"-O", "-T4"}
	
	// Add targets
	args = append(args, targets...)

	// Execute nmap
	ctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, "nmap", args...)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("nmap OS detection failed: %w", err)
	}

	// Parse nmap output (simplified)
	return ns.parseNmapOutput(string(output))
}

func (ns *NetworkScanner) parseNmapOutput(output string) ([]*entity.Asset, error) {
	// This is a simplified nmap output parser
	// In a production environment, you would want to use proper XML output parsing
	var assets []*entity.Asset
	
	lines := strings.Split(output, "\n")
	var currentHost string
	var currentAsset *entity.Asset
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		
		// Host detection
		if strings.HasPrefix(line, "Nmap scan report for") {
			if currentAsset != nil {
				assets = append(assets, currentAsset)
			}
			
			// Extract host
			parts := strings.Fields(line)
			if len(parts) >= 5 {
				currentHost = parts[4]
				currentAsset = ns.createBasicAsset(currentHost, entity.AssetTypeUnknown)
				currentAsset.DiscoveryMethod = "nmap"
			}
		}
		
		// Port information
		if strings.Contains(line, "/tcp") && strings.Contains(line, "open") && currentAsset != nil {
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				portStr := strings.Split(parts[0], "/")[0]
				if port, err := strconv.Atoi(portStr); err == nil {
					portInfo := entity.Port{
						Number:   port,
						Protocol: "tcp",
						State:    "open",
						Service:  parts[2],
					}
					
					if len(parts) > 3 {
						portInfo.Version = strings.Join(parts[3:], " ")
					}
					
					if currentAsset.NetworkInfo == nil {
						currentAsset.NetworkInfo = &entity.NetworkInfo{}
					}
					currentAsset.NetworkInfo.OpenPorts = append(currentAsset.NetworkInfo.OpenPorts, portInfo)
				}
			}
		}
		
		// OS information
		if strings.HasPrefix(line, "Running:") && currentAsset != nil {
			osInfo := strings.TrimPrefix(line, "Running: ")
			if currentAsset.SystemInfo == nil {
				currentAsset.SystemInfo = &entity.SystemInfo{}
			}
			currentAsset.SystemInfo.OperatingSystem = osInfo
		}
	}
	
	// Don't forget the last asset
	if currentAsset != nil {
		assets = append(assets, currentAsset)
	}
	
	return assets, nil
}