// iSECTECH SIEM Network Flow Collector
// High-performance NetFlow/sFlow/IPFIX collector for network security monitoring

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/Shopify/sarama"
	"github.com/go-redis/redis/v8"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
	"net/http"
)

// ═══════════════════════════════════════════════════════════════════════════════
// CONFIGURATION AND DATA STRUCTURES
// ═══════════════════════════════════════════════════════════════════════════════

type Config struct {
	Collector struct {
		NetFlowPort     int    `yaml:"netflow_port"`
		SFlowPort       int    `yaml:"sflow_port"`
		IPFIXPort       int    `yaml:"ipfix_port"`
		WorkerThreads   int    `yaml:"worker_threads"`
		BufferSize      int    `yaml:"buffer_size"`
		BatchSize       int    `yaml:"batch_size"`
		FlushInterval   string `yaml:"flush_interval"`
		MetricsPort     int    `yaml:"metrics_port"`
		SecurityEnabled bool   `yaml:"security_enabled"`
	} `yaml:"collector"`
	
	Kafka struct {
		Brokers           []string `yaml:"brokers"`
		Topic             string   `yaml:"topic"`
		SecurityTopic     string   `yaml:"security_topic"`
		CompressionType   string   `yaml:"compression_type"`
		BatchSize         int      `yaml:"batch_size"`
		LingerMs          int      `yaml:"linger_ms"`
		RequiredAcks      int      `yaml:"required_acks"`
	} `yaml:"kafka"`
	
	Redis struct {
		Host     string `yaml:"host"`
		Port     int    `yaml:"port"`
		Password string `yaml:"password"`
		DB       int    `yaml:"db"`
	} `yaml:"redis"`
	
	Security struct {
		SuspiciousPortsEnabled     bool     `yaml:"suspicious_ports_enabled"`
		SuspiciousPorts           []int    `yaml:"suspicious_ports"`
		GeolocationEnabled        bool     `yaml:"geolocation_enabled"`
		ThreatIntelEnabled        bool     `yaml:"threat_intel_enabled"`
		AnomalyDetectionEnabled   bool     `yaml:"anomaly_detection_enabled"`
		DDoSDetectionEnabled      bool     `yaml:"ddos_detection_enabled"`
		DDoSThresholdPPS          int      `yaml:"ddos_threshold_pps"`
		DDoSThresholdBPS          int64    `yaml:"ddos_threshold_bps"`
		BeaconingDetectionEnabled bool     `yaml:"beaconing_detection_enabled"`
	} `yaml:"security"`
	
	Logging struct {
		Level  string `yaml:"level"`
		Format string `yaml:"format"`
	} `yaml:"logging"`
}

// NetFlow v5 Header structure
type NetFlowV5Header struct {
	Version      uint16
	Count        uint16
	SysUptime    uint32
	UnixSecs     uint32
	UnixNanos    uint32
	FlowSequence uint32
	EngineType   uint8
	EngineID     uint8
	SampleRate   uint16
}

// NetFlow v5 Record structure
type NetFlowV5Record struct {
	SrcAddr   uint32
	DstAddr   uint32
	NextHop   uint32
	Input     uint16
	Output    uint16
	dPkts     uint32
	dOctets   uint32
	First     uint32
	Last      uint32
	SrcPort   uint16
	DstPort   uint16
	Pad1      uint8
	TCPFlags  uint8
	Prot      uint8
	Tos       uint8
	SrcAS     uint16
	DstAS     uint16
	SrcMask   uint8
	DstMask   uint8
	Pad2      uint16
}

// Processed flow record for SIEM
type FlowRecord struct {
	Timestamp       time.Time `json:"timestamp"`
	SourceIP        string    `json:"source_ip"`
	DestinationIP   string    `json:"destination_ip"`
	SourcePort      int       `json:"source_port"`
	DestinationPort int       `json:"destination_port"`
	Protocol        string    `json:"protocol"`
	Packets         uint64    `json:"packets"`
	Bytes           uint64    `json:"bytes"`
	Duration        float64   `json:"duration"`
	TCPFlags        []string  `json:"tcp_flags,omitempty"`
	
	// Device information
	DeviceIP      string `json:"device_ip"`
	DeviceType    string `json:"device_type"`
	InputIface    int    `json:"input_interface"`
	OutputIface   int    `json:"output_interface"`
	
	// Enrichment data
	SourceCountry      string  `json:"source_country,omitempty"`
	DestinationCountry string  `json:"destination_country,omitempty"`
	ThreatScore        int     `json:"threat_score"`
	Suspicious         bool    `json:"suspicious"`
	SecurityTags       []string `json:"security_tags,omitempty"`
	
	// Flow metadata
	FlowDirection     string  `json:"flow_direction"`
	IsInternal        bool    `json:"is_internal"`
	PacketsPerSecond  float64 `json:"packets_per_second"`
	BytesPerSecond    float64 `json:"bytes_per_second"`
	
	// Alert information
	AlertPriority     string   `json:"alert_priority"`
	AlertType         []string `json:"alert_type,omitempty"`
	RiskScore         int      `json:"risk_score"`
	
	// Additional metadata
	CollectorID     string `json:"collector_id"`
	ProcessingTime  int64  `json:"processing_time_ns"`
	Environment     string `json:"environment"`
	TenantID        string `json:"tenant_id"`
}

// Security analytics result
type SecurityAnalysis struct {
	DDoSDetected          bool     `json:"ddos_detected"`
	BeaconingDetected     bool     `json:"beaconing_detected"`
	SuspiciousPort        bool     `json:"suspicious_port"`
	ExternalCommunication bool     `json:"external_communication"`
	ThreatIntelMatch      bool     `json:"threat_intel_match"`
	AnomalyScore          float64  `json:"anomaly_score"`
	SecurityTags          []string `json:"security_tags"`
	AlertTypes            []string `json:"alert_types"`
}

// ═══════════════════════════════════════════════════════════════════════════════
// PROMETHEUS METRICS
// ═══════════════════════════════════════════════════════════════════════════════

var (
	flowsProcessedTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "netflow_flows_processed_total",
			Help: "Total number of network flows processed",
		},
		[]string{"device", "protocol", "status"},
	)
	
	flowProcessingDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name: "netflow_processing_duration_seconds",
			Help: "Time spent processing network flows",
		},
		[]string{"device"},
	)
	
	securityAlertsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "netflow_security_alerts_total",
			Help: "Total security alerts generated from network flows",
		},
		[]string{"device", "alert_type"},
	)
	
	bytesProcessedTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "netflow_bytes_processed_total",
			Help: "Total bytes processed in network flows",
		},
		[]string{"device", "direction"},
	)
	
	packetsProcessedTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "netflow_packets_processed_total",
			Help: "Total packets processed in network flows",
		},
		[]string{"device", "direction"},
	)
	
	activeFlows = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "netflow_active_flows",
			Help: "Number of active network flows being processed",
		},
		[]string{"device"},
	)
)

func init() {
	prometheus.MustRegister(flowsProcessedTotal)
	prometheus.MustRegister(flowProcessingDuration)
	prometheus.MustRegister(securityAlertsTotal)
	prometheus.MustRegister(bytesProcessedTotal)
	prometheus.MustRegister(packetsProcessedTotal)
	prometheus.MustRegister(activeFlows)
}

// ═══════════════════════════════════════════════════════════════════════════════
// FLOW COLLECTOR CLASS
// ═══════════════════════════════════════════════════════════════════════════════

type FlowCollector struct {
	config       *Config
	logger       *logrus.Logger
	kafkaClient  sarama.SyncProducer
	redisClient  *redis.Client
	
	// Network listeners
	netflowConn net.PacketConn
	sflowConn   net.PacketConn
	ipfixConn   net.PacketConn
	
	// Processing
	ctx          context.Context
	cancel       context.CancelFunc
	wg           sync.WaitGroup
	flowBuffer   chan *FlowRecord
	
	// Security components
	suspiciousPorts  map[int]bool
	internalNetworks []*net.IPNet
	
	// Statistics
	stats struct {
		sync.RWMutex
		flowsProcessed   uint64
		bytesProcessed   uint64
		packetsProcessed uint64
		alertsGenerated  uint64
		errorsEncountered uint64
	}
}

func NewFlowCollector(configFile string) (*FlowCollector, error) {
	// Load configuration
	config, err := loadConfig(configFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}
	
	// Setup logger
	logger := logrus.New()
	level, err := logrus.ParseLevel(config.Logging.Level)
	if err != nil {
		level = logrus.InfoLevel
	}
	logger.SetLevel(level)
	
	if config.Logging.Format == "json" {
		logger.SetFormatter(&logrus.JSONFormatter{})
	}
	
	// Create context
	ctx, cancel := context.WithCancel(context.Background())
	
	collector := &FlowCollector{
		config:     config,
		logger:     logger,
		ctx:        ctx,
		cancel:     cancel,
		flowBuffer: make(chan *FlowRecord, config.Collector.BufferSize),
	}
	
	// Initialize suspicious ports map
	collector.suspiciousPorts = make(map[int]bool)
	for _, port := range config.Security.SuspiciousPorts {
		collector.suspiciousPorts[port] = true
	}
	
	// Initialize internal networks
	collector.initializeInternalNetworks()
	
	return collector, nil
}

func loadConfig(filename string) (*Config, error) {
	file, err := os.Open(filename)
	if err != nil {
		// Return default config if file doesn't exist
		return getDefaultConfig(), nil
	}
	defer file.Close()
	
	config := &Config{}
	decoder := yaml.NewDecoder(file)
	err = decoder.Decode(config)
	if err != nil {
		return nil, err
	}
	
	return config, nil
}

func getDefaultConfig() *Config {
	return &Config{
		Collector: struct {
			NetFlowPort     int    `yaml:"netflow_port"`
			SFlowPort       int    `yaml:"sflow_port"`
			IPFIXPort       int    `yaml:"ipfix_port"`
			WorkerThreads   int    `yaml:"worker_threads"`
			BufferSize      int    `yaml:"buffer_size"`
			BatchSize       int    `yaml:"batch_size"`
			FlushInterval   string `yaml:"flush_interval"`
			MetricsPort     int    `yaml:"metrics_port"`
			SecurityEnabled bool   `yaml:"security_enabled"`
		}{
			NetFlowPort:     2055,
			SFlowPort:       6343,
			IPFIXPort:       4739,
			WorkerThreads:   10,
			BufferSize:      10000,
			BatchSize:       1000,
			FlushInterval:   "5s",
			MetricsPort:     9162,
			SecurityEnabled: true,
		},
		Kafka: struct {
			Brokers           []string `yaml:"brokers"`
			Topic             string   `yaml:"topic"`
			SecurityTopic     string   `yaml:"security_topic"`
			CompressionType   string   `yaml:"compression_type"`
			BatchSize         int      `yaml:"batch_size"`
			LingerMs          int      `yaml:"linger_ms"`
			RequiredAcks      int      `yaml:"required_acks"`
		}{
			Brokers:         []string{"kafka-1.isectech.local:9092"},
			Topic:           "network-flows",
			SecurityTopic:   "network-security-alerts",
			CompressionType: "gzip",
			BatchSize:       1000,
			LingerMs:        1000,
			RequiredAcks:    1,
		},
		Security: struct {
			SuspiciousPortsEnabled     bool     `yaml:"suspicious_ports_enabled"`
			SuspiciousPorts           []int    `yaml:"suspicious_ports"`
			GeolocationEnabled        bool     `yaml:"geolocation_enabled"`
			ThreatIntelEnabled        bool     `yaml:"threat_intel_enabled"`
			AnomalyDetectionEnabled   bool     `yaml:"anomaly_detection_enabled"`
			DDoSDetectionEnabled      bool     `yaml:"ddos_detection_enabled"`
			DDoSThresholdPPS          int      `yaml:"ddos_threshold_pps"`
			DDoSThresholdBPS          int64    `yaml:"ddos_threshold_bps"`
			BeaconingDetectionEnabled bool     `yaml:"beaconing_detection_enabled"`
		}{
			SuspiciousPortsEnabled:     true,
			SuspiciousPorts:           []int{22, 23, 135, 139, 445, 1433, 3389, 5432, 5900, 6379},
			GeolocationEnabled:        true,
			ThreatIntelEnabled:        true,
			AnomalyDetectionEnabled:   true,
			DDoSDetectionEnabled:      true,
			DDoSThresholdPPS:          10000,
			DDoSThresholdBPS:          100000000, // 100 Mbps
			BeaconingDetectionEnabled: true,
		},
		Logging: struct {
			Level  string `yaml:"level"`
			Format string `yaml:"format"`
		}{
			Level:  "info",
			Format: "json",
		},
	}
}

func (fc *FlowCollector) initializeInternalNetworks() {
	// Define internal network ranges
	internalRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
	}
	
	for _, cidr := range internalRanges {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			fc.logger.WithError(err).Warn("Failed to parse internal network CIDR")
			continue
		}
		fc.internalNetworks = append(fc.internalNetworks, network)
	}
}

func (fc *FlowCollector) Initialize() error {
	fc.logger.Info("Initializing flow collector")
	
	// Initialize Kafka producer
	config := sarama.NewConfig()
	config.Producer.RequiredAcks = sarama.WaitForAll
	config.Producer.Retry.Max = 3
	config.Producer.Return.Successes = true
	
	switch fc.config.Kafka.CompressionType {
	case "gzip":
		config.Producer.Compression = sarama.CompressionGZIP
	case "snappy":
		config.Producer.Compression = sarama.CompressionSnappy
	case "lz4":
		config.Producer.Compression = sarama.CompressionLZ4
	}
	
	producer, err := sarama.NewSyncProducer(fc.config.Kafka.Brokers, config)
	if err != nil {
		return fmt.Errorf("failed to create Kafka producer: %w", err)
	}
	fc.kafkaClient = producer
	
	// Initialize Redis client
	fc.redisClient = redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%d", fc.config.Redis.Host, fc.config.Redis.Port),
		Password: fc.config.Redis.Password,
		DB:       fc.config.Redis.DB,
	})
	
	// Test Redis connection
	_, err = fc.redisClient.Ping(fc.ctx).Result()
	if err != nil {
		fc.logger.WithError(err).Warn("Failed to connect to Redis")
	}
	
	// Setup network listeners
	if err := fc.setupNetworkListeners(); err != nil {
		return fmt.Errorf("failed to setup network listeners: %w", err)
	}
	
	// Start metrics server
	fc.startMetricsServer()
	
	fc.logger.Info("Flow collector initialized successfully")
	return nil
}

func (fc *FlowCollector) setupNetworkListeners() error {
	// NetFlow listener
	netflowAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", fc.config.Collector.NetFlowPort))
	if err != nil {
		return err
	}
	fc.netflowConn, err = net.ListenUDP("udp", netflowAddr)
	if err != nil {
		return err
	}
	
	// sFlow listener
	sflowAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", fc.config.Collector.SFlowPort))
	if err != nil {
		return err
	}
	fc.sflowConn, err = net.ListenUDP("udp", sflowAddr)
	if err != nil {
		return err
	}
	
	// IPFIX listener
	ipfixAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", fc.config.Collector.IPFIXPort))
	if err != nil {
		return err
	}
	fc.ipfixConn, err = net.ListenUDP("udp", ipfixAddr)
	if err != nil {
		return err
	}
	
	fc.logger.WithFields(logrus.Fields{
		"netflow_port": fc.config.Collector.NetFlowPort,
		"sflow_port":   fc.config.Collector.SFlowPort,
		"ipfix_port":   fc.config.Collector.IPFIXPort,
	}).Info("Network listeners setup complete")
	
	return nil
}

func (fc *FlowCollector) startMetricsServer() {
	go func() {
		http.Handle("/metrics", promhttp.Handler())
		http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("OK"))
		})
		
		addr := fmt.Sprintf(":%d", fc.config.Collector.MetricsPort)
		fc.logger.WithField("addr", addr).Info("Starting metrics server")
		if err := http.ListenAndServe(addr, nil); err != nil {
			fc.logger.WithError(err).Error("Metrics server failed")
		}
	}()
}

func (fc *FlowCollector) Start() error {
	fc.logger.Info("Starting flow collector")
	
	// Start flow processors
	for i := 0; i < fc.config.Collector.WorkerThreads; i++ {
		fc.wg.Add(1)
		go fc.flowProcessor(i)
	}
	
	// Start network listeners
	fc.wg.Add(1)
	go fc.netflowListener()
	
	fc.wg.Add(1) 
	go fc.sflowListener()
	
	fc.wg.Add(1)
	go fc.ipfixListener()
	
	// Start statistics reporter
	fc.wg.Add(1)
	go fc.statisticsReporter()
	
	fc.logger.Info("Flow collector started successfully")
	return nil
}

func (fc *FlowCollector) Stop() error {
	fc.logger.Info("Stopping flow collector")
	
	// Cancel context
	fc.cancel()
	
	// Close network connections
	if fc.netflowConn != nil {
		fc.netflowConn.Close()
	}
	if fc.sflowConn != nil {
		fc.sflowConn.Close()
	}
	if fc.ipfixConn != nil {
		fc.ipfixConn.Close()
	}
	
	// Close channels
	close(fc.flowBuffer)
	
	// Wait for workers to finish
	fc.wg.Wait()
	
	// Close clients
	if fc.kafkaClient != nil {
		fc.kafkaClient.Close()
	}
	if fc.redisClient != nil {
		fc.redisClient.Close()
	}
	
	fc.logger.Info("Flow collector stopped")
	return nil
}

func (fc *FlowCollector) netflowListener() {
	defer fc.wg.Done()
	
	buffer := make([]byte, 65536)
	
	for {
		select {
		case <-fc.ctx.Done():
			return
		default:
			n, addr, err := fc.netflowConn.ReadFrom(buffer)
			if err != nil {
				if fc.ctx.Err() != nil {
					return
				}
				fc.logger.WithError(err).Error("Failed to read NetFlow packet")
				continue
			}
			
			go fc.processNetFlowPacket(buffer[:n], addr.String())
		}
	}
}

func (fc *FlowCollector) sflowListener() {
	defer fc.wg.Done()
	
	buffer := make([]byte, 65536)
	
	for {
		select {
		case <-fc.ctx.Done():
			return
		default:
			n, addr, err := fc.sflowConn.ReadFrom(buffer)
			if err != nil {
				if fc.ctx.Err() != nil {
					return
				}
				fc.logger.WithError(err).Error("Failed to read sFlow packet")
				continue
			}
			
			go fc.processSFlowPacket(buffer[:n], addr.String())
		}
	}
}

func (fc *FlowCollector) ipfixListener() {
	defer fc.wg.Done()
	
	buffer := make([]byte, 65536)
	
	for {
		select {
		case <-fc.ctx.Done():
			return
		default:
			n, addr, err := fc.ipfixConn.ReadFrom(buffer)
			if err != nil {
				if fc.ctx.Err() != nil {
					return
				}
				fc.logger.WithError(err).Error("Failed to read IPFIX packet")
				continue
			}
			
			go fc.processIPFIXPacket(buffer[:n], addr.String())
		}
	}
}

func (fc *FlowCollector) processNetFlowPacket(data []byte, deviceIP string) {
	start := time.Now()
	defer func() {
		flowProcessingDuration.WithLabelValues(deviceIP).Observe(time.Since(start).Seconds())
	}()
	
	// Simple NetFlow v5 parsing (would need full implementation for production)
	if len(data) < 24 { // Minimum header size
		fc.logger.Warn("NetFlow packet too small")
		return
	}
	
	// Parse header (simplified)
	version := uint16(data[0])<<8 | uint16(data[1])
	count := uint16(data[2])<<8 | uint16(data[3])
	
	if version != 5 {
		fc.logger.WithField("version", version).Debug("Unsupported NetFlow version")
		return
	}
	
	// Process each flow record
	recordOffset := 24 // After header
	recordSize := 48   // NetFlow v5 record size
	
	for i := 0; i < int(count); i++ {
		if recordOffset+recordSize > len(data) {
			break
		}
		
		record := fc.parseNetFlowV5Record(data[recordOffset:recordOffset+recordSize], deviceIP)
		if record != nil {
			select {
			case fc.flowBuffer <- record:
			default:
				fc.logger.Warn("Flow buffer full, dropping record")
			}
		}
		
		recordOffset += recordSize
	}
}

func (fc *FlowCollector) parseNetFlowV5Record(data []byte, deviceIP string) *FlowRecord {
	if len(data) < 48 {
		return nil
	}
	
	// Parse NetFlow v5 record fields (simplified parsing)
	srcIP := fmt.Sprintf("%d.%d.%d.%d", data[0], data[1], data[2], data[3])
	dstIP := fmt.Sprintf("%d.%d.%d.%d", data[4], data[5], data[6], data[7])
	
	srcPort := int(uint16(data[20])<<8 | uint16(data[21]))
	dstPort := int(uint16(data[22])<<8 | uint16(data[23]))
	
	protocol := data[25]
	protocolName := getProtocolName(protocol)
	
	packets := uint64(uint32(data[16])<<24 | uint32(data[17])<<16 | uint32(data[18])<<8 | uint32(data[19]))
	bytes := uint64(uint32(data[20])<<24 | uint32(data[21])<<16 | uint32(data[22])<<8 | uint32(data[23]))
	
	first := uint32(data[24])<<24 | uint32(data[25])<<16 | uint32(data[26])<<8 | uint32(data[27])
	last := uint32(data[28])<<24 | uint32(data[29])<<16 | uint32(data[30])<<8 | uint32(data[31])
	
	duration := float64(last-first) / 1000.0 // Convert to seconds
	
	record := &FlowRecord{
		Timestamp:       time.Now(),
		SourceIP:        srcIP,
		DestinationIP:   dstIP,
		SourcePort:      srcPort,
		DestinationPort: dstPort,
		Protocol:        protocolName,
		Packets:         packets,
		Bytes:           bytes,
		Duration:        duration,
		DeviceIP:        deviceIP,
		DeviceType:      "router", // Would be determined from device inventory
		CollectorID:     "netflow-collector-01",
		Environment:     "production",
		TenantID:        "isectech",
		ProcessingTime:  time.Now().UnixNano(),
	}
	
	// Calculate rates
	if duration > 0 {
		record.PacketsPerSecond = float64(packets) / duration
		record.BytesPerSecond = float64(bytes) / duration
	}
	
	// Determine if internal/external
	record.IsInternal = fc.isInternalIP(srcIP) && fc.isInternalIP(dstIP)
	if fc.isInternalIP(srcIP) && !fc.isInternalIP(dstIP) {
		record.FlowDirection = "outbound"
	} else if !fc.isInternalIP(srcIP) && fc.isInternalIP(dstIP) {
		record.FlowDirection = "inbound"
	} else {
		record.FlowDirection = "internal"
	}
	
	return record
}

func (fc *FlowCollector) processSFlowPacket(data []byte, deviceIP string) {
	// sFlow processing would be implemented here
	fc.logger.Debug("Processing sFlow packet")
}

func (fc *FlowCollector) processIPFIXPacket(data []byte, deviceIP string) {
	// IPFIX processing would be implemented here
	fc.logger.Debug("Processing IPFIX packet")
}

func (fc *FlowCollector) flowProcessor(workerID int) {
	defer fc.wg.Done()
	
	logger := fc.logger.WithField("worker", workerID)
	logger.Info("Starting flow processor")
	
	batch := make([]*FlowRecord, 0, fc.config.Collector.BatchSize)
	
	flushInterval, _ := time.ParseDuration(fc.config.Collector.FlushInterval)
	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-fc.ctx.Done():
			// Process remaining batch
			if len(batch) > 0 {
				fc.processBatch(batch)
			}
			return
			
		case record, ok := <-fc.flowBuffer:
			if !ok {
				return
			}
			
			// Enrich record with security analysis
			if fc.config.Collector.SecurityEnabled {
				fc.enrichWithSecurityAnalysis(record)
			}
			
			batch = append(batch, record)
			
			// Process batch when full
			if len(batch) >= fc.config.Collector.BatchSize {
				fc.processBatch(batch)
				batch = batch[:0]
			}
			
		case <-ticker.C:
			// Process batch on timer
			if len(batch) > 0 {
				fc.processBatch(batch)
				batch = batch[:0]
			}
		}
	}
}

func (fc *FlowCollector) enrichWithSecurityAnalysis(record *FlowRecord) {
	analysis := fc.performSecurityAnalysis(record)
	
	record.ThreatScore = int(analysis.AnomalyScore * 10)
	record.Suspicious = analysis.DDoSDetected || analysis.BeaconingDetected || 
	                   analysis.SuspiciousPort || analysis.ThreatIntelMatch
	record.SecurityTags = analysis.SecurityTags
	record.AlertType = analysis.AlertTypes
	
	// Calculate risk score
	riskScore := 0
	
	if analysis.DDoSDetected {
		riskScore += 8
	}
	if analysis.BeaconingDetected {
		riskScore += 6
	}
	if analysis.SuspiciousPort {
		riskScore += 4
	}
	if analysis.ExternalCommunication && !record.IsInternal {
		riskScore += 2
	}
	if analysis.ThreatIntelMatch {
		riskScore += 7
	}
	
	record.RiskScore = riskScore
	
	// Set alert priority
	if riskScore >= 8 {
		record.AlertPriority = "critical"
	} else if riskScore >= 6 {
		record.AlertPriority = "high"
	} else if riskScore >= 4 {
		record.AlertPriority = "medium"
	} else {
		record.AlertPriority = "low"
	}
}

func (fc *FlowCollector) performSecurityAnalysis(record *FlowRecord) *SecurityAnalysis {
	analysis := &SecurityAnalysis{
		SecurityTags: []string{},
		AlertTypes:   []string{},
	}
	
	// Check for suspicious ports
	if fc.config.Security.SuspiciousPortsEnabled {
		if fc.suspiciousPorts[record.DestinationPort] {
			analysis.SuspiciousPort = true
			analysis.SecurityTags = append(analysis.SecurityTags, "suspicious_port")
			analysis.AlertTypes = append(analysis.AlertTypes, "suspicious_port_access")
		}
	}
	
	// Check for DDoS patterns
	if fc.config.Security.DDoSDetectionEnabled {
		if record.PacketsPerSecond > float64(fc.config.Security.DDoSThresholdPPS) ||
		   record.BytesPerSecond > float64(fc.config.Security.DDoSThresholdBPS) {
			analysis.DDoSDetected = true
			analysis.SecurityTags = append(analysis.SecurityTags, "ddos")
			analysis.AlertTypes = append(analysis.AlertTypes, "ddos_attack")
		}
	}
	
	// Check for external communication
	if !record.IsInternal {
		analysis.ExternalCommunication = true
		analysis.SecurityTags = append(analysis.SecurityTags, "external_communication")
		
		// Additional checks for external communication
		if record.DestinationPort == 22 || record.DestinationPort == 3389 {
			analysis.AlertTypes = append(analysis.AlertTypes, "external_admin_access")
		}
	}
	
	// Beaconing detection (simplified)
	if fc.config.Security.BeaconingDetectionEnabled {
		// Would implement actual beaconing detection logic here
		if record.Packets < 10 && record.Duration > 0 && record.Duration < 1.0 {
			// Potential beaconing pattern
			analysis.BeaconingDetected = true
			analysis.SecurityTags = append(analysis.SecurityTags, "beaconing")
			analysis.AlertTypes = append(analysis.AlertTypes, "beaconing_detected")
		}
	}
	
	// Calculate anomaly score (simplified)
	analysis.AnomalyScore = 0.0
	if analysis.DDoSDetected {
		analysis.AnomalyScore += 0.8
	}
	if analysis.SuspiciousPort {
		analysis.AnomalyScore += 0.6
	}
	if analysis.BeaconingDetected {
		analysis.AnomalyScore += 0.7
	}
	if analysis.ExternalCommunication {
		analysis.AnomalyScore += 0.3
	}
	
	return analysis
}

func (fc *FlowCollector) processBatch(batch []*FlowRecord) {
	// Update statistics
	fc.stats.Lock()
	fc.stats.flowsProcessed += uint64(len(batch))
	fc.stats.Unlock()
	
	// Send to Kafka
	for _, record := range batch {
		fc.sendToKafka(record)
		
		// Update metrics
		flowsProcessedTotal.WithLabelValues(record.DeviceIP, record.Protocol, "success").Inc()
		bytesProcessedTotal.WithLabelValues(record.DeviceIP, record.FlowDirection).Add(float64(record.Bytes))
		packetsProcessedTotal.WithLabelValues(record.DeviceIP, record.FlowDirection).Add(float64(record.Packets))
		
		// Generate security alerts if needed
		if record.Suspicious {
			for _, alertType := range record.AlertType {
				securityAlertsTotal.WithLabelValues(record.DeviceIP, alertType).Inc()
			}
			fc.sendSecurityAlert(record)
		}
		
		// Cache in Redis for quick access
		fc.cacheFlowRecord(record)
	}
}

func (fc *FlowCollector) sendToKafka(record *FlowRecord) {
	data, err := json.Marshal(record)
	if err != nil {
		fc.logger.WithError(err).Error("Failed to marshal flow record")
		return
	}
	
	message := &sarama.ProducerMessage{
		Topic: fc.config.Kafka.Topic,
		Key:   sarama.StringEncoder(fmt.Sprintf("%s:%s", record.SourceIP, record.DestinationIP)),
		Value: sarama.ByteEncoder(data),
	}
	
	_, _, err = fc.kafkaClient.SendMessage(message)
	if err != nil {
		fc.logger.WithError(err).Error("Failed to send message to Kafka")
	}
}

func (fc *FlowCollector) sendSecurityAlert(record *FlowRecord) {
	alert := map[string]interface{}{
		"alert_id":       fmt.Sprintf("netflow_%d_%s", time.Now().UnixNano(), record.SourceIP),
		"timestamp":      record.Timestamp,
		"alert_type":     record.AlertType,
		"severity":       record.AlertPriority,
		"source_ip":      record.SourceIP,
		"destination_ip": record.DestinationIP,
		"source_port":    record.SourcePort,
		"destination_port": record.DestinationPort,
		"protocol":       record.Protocol,
		"risk_score":     record.RiskScore,
		"threat_score":   record.ThreatScore,
		"security_tags":  record.SecurityTags,
		"device_ip":      record.DeviceIP,
		"flow_direction": record.FlowDirection,
		"raw_flow":       record,
	}
	
	data, err := json.Marshal(alert)
	if err != nil {
		fc.logger.WithError(err).Error("Failed to marshal security alert")
		return
	}
	
	message := &sarama.ProducerMessage{
		Topic: fc.config.Kafka.SecurityTopic,
		Key:   sarama.StringEncoder(record.SourceIP),
		Value: sarama.ByteEncoder(data),
	}
	
	_, _, err = fc.kafkaClient.SendMessage(message)
	if err != nil {
		fc.logger.WithError(err).Error("Failed to send security alert to Kafka")
	}
}

func (fc *FlowCollector) cacheFlowRecord(record *FlowRecord) {
	if fc.redisClient == nil {
		return
	}
	
	key := fmt.Sprintf("flow:%s:%s:%d:%d", record.SourceIP, record.DestinationIP, 
	                   record.SourcePort, record.DestinationPort)
	
	data, err := json.Marshal(record)
	if err != nil {
		return
	}
	
	// Cache for 1 hour
	fc.redisClient.Set(fc.ctx, key, data, time.Hour)
}

func (fc *FlowCollector) statisticsReporter() {
	defer fc.wg.Done()
	
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-fc.ctx.Done():
			return
		case <-ticker.C:
			fc.stats.RLock()
			fc.logger.WithFields(logrus.Fields{
				"flows_processed":    fc.stats.flowsProcessed,
				"bytes_processed":    fc.stats.bytesProcessed,
				"packets_processed":  fc.stats.packetsProcessed,
				"alerts_generated":   fc.stats.alertsGenerated,
				"errors_encountered": fc.stats.errorsEncountered,
			}).Info("Flow collector statistics")
			fc.stats.RUnlock()
		}
	}
}

// Helper functions
func (fc *FlowCollector) isInternalIP(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}
	
	for _, network := range fc.internalNetworks {
		if network.Contains(parsedIP) {
			return true
		}
	}
	return false
}

func getProtocolName(protocol uint8) string {
	switch protocol {
	case 1:
		return "icmp"
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 47:
		return "gre"
	case 50:
		return "esp"
	case 51:
		return "ah"
	default:
		return fmt.Sprintf("proto-%d", protocol)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// MAIN EXECUTION
// ═══════════════════════════════════════════════════════════════════════════════

func main() {
	configFile := "/etc/isectech-siem/netflow-collector.yaml"
	if len(os.Args) > 1 {
		configFile = os.Args[1]
	}
	
	collector, err := NewFlowCollector(configFile)
	if err != nil {
		log.Fatalf("Failed to create flow collector: %v", err)
	}
	
	// Initialize collector
	if err := collector.Initialize(); err != nil {
		log.Fatalf("Failed to initialize collector: %v", err)
	}
	
	// Setup signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	
	// Start collector
	go func() {
		if err := collector.Start(); err != nil {
			log.Fatalf("Failed to start collector: %v", err)
		}
	}()
	
	// Wait for shutdown signal
	<-sigChan
	log.Println("Shutting down flow collector...")
	
	if err := collector.Stop(); err != nil {
		log.Printf("Error stopping collector: %v", err)
	}
	
	log.Println("Flow collector stopped")
}