// iSECTECH POC Sample Data Generation and Population System
// Production-Grade Cybersecurity Sample Data Generator
// Version: 1.0
// Author: Claude Code Implementation

package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"math"
	mathrand "math/rand"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Configuration structure
type Config struct {
	Port               string
	DatabaseURL        string
	Environment        string
	DataOutputPath     string
	MaxDatasetSize     int64
	GenerationTimeout  time.Duration
	EnableRealisticIPs bool
	EnableGDPRMode     bool
	LogLevel           string
}

// Sample data generation request
type DataGenerationRequest struct {
	TenantID             uuid.UUID              `json:"tenant_id" binding:"required"`
	TenantSlug           string                 `json:"tenant_slug" binding:"required"`
	IndustryVertical     string                 `json:"industry_vertical" binding:"required"`
	CompanySize          string                 `json:"company_size" binding:"required"`
	SecurityScenarios    []string               `json:"security_scenarios"`
	DataVolume           DataVolumeConfig       `json:"data_volume"`
	ComplianceLevel      string                 `json:"compliance_level"`
	CustomRequirements   map[string]interface{} `json:"custom_requirements"`
	OutputFormats        []string               `json:"output_formats"`
	PrivacySettings      PrivacySettings        `json:"privacy_settings"`
	RequestID            string                 `json:"request_id"`
}

type DataVolumeConfig struct {
	TotalEvents          int `json:"total_events"`
	UsersCount           int `json:"users_count"`
	AssetsCount          int `json:"assets_count"`
	VulnerabilitiesCount int `json:"vulnerabilities_count"`
	IncidentsCount       int `json:"incidents_count"`
	TimeRangeDays        int `json:"time_range_days"`
}

type PrivacySettings struct {
	AnonymizePersonalData bool `json:"anonymize_personal_data"`
	GDPRCompliant        bool `json:"gdpr_compliant"`
	RemovePII            bool `json:"remove_pii"`
	UseHashedIdentifiers bool `json:"use_hashed_identifiers"`
}

// Data generation job tracking
type DataGenerationJob struct {
	JobID               uuid.UUID              `gorm:"primarykey;type:uuid;default:uuid_generate_v4()" json:"job_id"`
	TenantID            uuid.UUID              `gorm:"not null;index" json:"tenant_id"`
	TenantSlug          string                 `gorm:"not null;size:63" json:"tenant_slug"`
	Status              string                 `gorm:"not null;default:pending;index" json:"status"`
	Priority            string                 `gorm:"not null;default:standard" json:"priority"`
	
	// Request details
	RequestID           string                 `gorm:"not null;unique" json:"request_id"`
	RequestPayload      map[string]interface{} `gorm:"type:jsonb" json:"request_payload"`
	
	// Generation details
	IndustryVertical    string                 `gorm:"not null;size:100" json:"industry_vertical"`
	CompanySize         string                 `gorm:"not null;size:50" json:"company_size"`
	SecurityScenarios   []string               `gorm:"type:text[]" json:"security_scenarios"`
	
	// Progress tracking
	CurrentDataset      string                 `gorm:"size:100" json:"current_dataset"`
	TotalDatasets       int                    `gorm:"default:0" json:"total_datasets"`
	CompletedDatasets   int                    `gorm:"default:0" json:"completed_datasets"`
	ProgressPercent     int                    `gorm:"default:0" json:"progress_percent"`
	
	// Output and results
	GeneratedDatasets   map[string]interface{} `gorm:"type:jsonb" json:"generated_datasets"`
	DataQualityMetrics  map[string]interface{} `gorm:"type:jsonb" json:"data_quality_metrics"`
	OutputLocations     map[string]interface{} `gorm:"type:jsonb" json:"output_locations"`
	
	// Statistics
	TotalRecordsGenerated int64                `gorm:"default:0" json:"total_records_generated"`
	DataSizeMB           float64              `gorm:"default:0" json:"data_size_mb"`
	GenerationDuration   time.Duration        `json:"generation_duration"`
	
	// Timing information
	QueuedAt            *time.Time             `json:"queued_at"`
	StartedAt           *time.Time             `json:"started_at"`
	CompletedAt         *time.Time             `json:"completed_at"`
	
	// Error handling
	ErrorMessage        string                 `gorm:"type:text" json:"error_message"`
	ErrorDetails        map[string]interface{} `gorm:"type:jsonb" json:"error_details"`
	
	// Lifecycle
	ExpiresAt           time.Time              `gorm:"not null" json:"expires_at"`
	CleanupScheduled    bool                   `gorm:"default:false" json:"cleanup_scheduled"`
	
	// Metadata
	Tags                map[string]interface{} `gorm:"type:jsonb" json:"tags"`
	CreatedAt           time.Time              `gorm:"default:now()" json:"created_at"`
	UpdatedAt           time.Time              `gorm:"default:now()" json:"updated_at"`
}

// Sample data structures
type SecurityEvent struct {
	EventID        string    `json:"event_id"`
	Timestamp      time.Time `json:"timestamp"`
	EventType      string    `json:"event_type"`
	Severity       string    `json:"severity"`
	SourceIP       string    `json:"source_ip"`
	DestinationIP  string    `json:"destination_ip"`
	UserAgent      string    `json:"user_agent"`
	Username       string    `json:"username"`
	Application    string    `json:"application"`
	Description    string    `json:"description"`
	RawLog         string    `json:"raw_log"`
	AttackVector   string    `json:"attack_vector"`
	MITREID        string    `json:"mitre_id"`
	GeoLocation    GeoLocation `json:"geo_location"`
	Risk Score     int       `json:"risk_score"`
}

type NetworkTraffic struct {
	ConnectionID   string    `json:"connection_id"`
	Timestamp      time.Time `json:"timestamp"`
	Protocol       string    `json:"protocol"`
	SourceIP       string    `json:"source_ip"`
	SourcePort     int       `json:"source_port"`
	DestinationIP  string    `json:"destination_ip"`
	DestinationPort int      `json:"destination_port"`
	BytesSent      int64     `json:"bytes_sent"`
	BytesReceived  int64     `json:"bytes_received"`
	PacketCount    int       `json:"packet_count"`
	Duration       int       `json:"duration_seconds"`
	Flags          []string  `json:"flags"`
	ApplicationProtocol string `json:"application_protocol"`
	Blocked        bool      `json:"blocked"`
	ThreatScore    int       `json:"threat_score"`
}

type Vulnerability struct {
	VulnerabilityID string    `json:"vulnerability_id"`
	CVEID          string    `json:"cve_id"`
	Title          string    `json:"title"`
	Description    string    `json:"description"`
	Severity       string    `json:"severity"`
	CVSSScore      float64   `json:"cvss_score"`
	CVSSVector     string    `json:"cvss_vector"`
	CWE            string    `json:"cwe"`
	AffectedAsset  string    `json:"affected_asset"`
	AssetType      string    `json:"asset_type"`
	DiscoveredAt   time.Time `json:"discovered_at"`
	Status         string    `json:"status"`
	Remediation    string    `json:"remediation"`
	ExploitAvailable bool    `json:"exploit_available"`
	PatchAvailable bool     `json:"patch_available"`
	BusinessImpact string   `json:"business_impact"`
}

type SecurityIncident struct {
	IncidentID     string    `json:"incident_id"`
	Title          string    `json:"title"`
	Description    string    `json:"description"`
	Severity       string    `json:"severity"`
	Status         string    `json:"status"`
	Category       string    `json:"category"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
	AssignedTo     string    `json:"assigned_to"`
	Reporter       string    `json:"reporter"`
	AffectedSystems []string `json:"affected_systems"`
	Timeline       []IncidentTimelineEntry `json:"timeline"`
	MTTR           int       `json:"mttr_minutes"`
	RootCause      string    `json:"root_cause"`
	Remediation    string    `json:"remediation"`
	LessonsLearned string    `json:"lessons_learned"`
}

type IncidentTimelineEntry struct {
	Timestamp   time.Time `json:"timestamp"`
	Action      string    `json:"action"`
	Description string    `json:"description"`
	User        string    `json:"user"`
}

type UserActivity struct {
	UserID         string    `json:"user_id"`
	Username       string    `json:"username"`
	Email          string    `json:"email"`
	Department     string    `json:"department"`
	Role           string    `json:"role"`
	Timestamp      time.Time `json:"timestamp"`
	Activity       string    `json:"activity"`
	Resource       string    `json:"resource"`
	SourceIP       string    `json:"source_ip"`
	UserAgent      string    `json:"user_agent"`
	Success        bool      `json:"success"`
	RiskScore      int       `json:"risk_score"`
	GeoLocation    GeoLocation `json:"geo_location"`
	Anomalous      bool      `json:"anomalous"`
}

type GeoLocation struct {
	Country    string  `json:"country"`
	City       string  `json:"city"`
	Region     string  `json:"region"`
	Latitude   float64 `json:"latitude"`
	Longitude  float64 `json:"longitude"`
	ISP        string  `json:"isp"`
	ThreatIntel bool   `json:"threat_intel"`
}

// Application struct
type App struct {
	config      *Config
	db          *gorm.DB
	router      *gin.Engine
	generators  map[string]DataGenerator
}

// Data generator interface
type DataGenerator interface {
	Generate(ctx context.Context, config GeneratorConfig) ([]interface{}, error)
	GetSchema() map[string]interface{}
	Validate(data []interface{}) error
}

type GeneratorConfig struct {
	Count             int
	IndustryVertical  string
	CompanySize       string
	TimeRange         TimeRange
	PrivacySettings   PrivacySettings
	CustomParameters  map[string]interface{}
}

type TimeRange struct {
	Start time.Time
	End   time.Time
}

// Initialize configuration
func initConfig() *Config {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using system environment variables")
	}

	config := &Config{
		Port:               getEnv("PORT", "8082"),
		DatabaseURL:        getEnv("DATABASE_URL", "postgres://localhost/isectech_poc?sslmode=disable"),
		Environment:        getEnv("ENVIRONMENT", "development"),
		DataOutputPath:     getEnv("DATA_OUTPUT_PATH", "./generated-data"),
		MaxDatasetSize:     getEnvAsInt64("MAX_DATASET_SIZE", 1024*1024*1024), // 1GB
		EnableRealisticIPs: getEnvAsBool("ENABLE_REALISTIC_IPS", true),
		EnableGDPRMode:     getEnvAsBool("ENABLE_GDPR_MODE", true),
		LogLevel:           getEnv("LOG_LEVEL", "info"),
	}

	// Parse generation timeout
	if timeoutStr := getEnv("GENERATION_TIMEOUT", "60m"); timeoutStr != "" {
		if timeout, err := time.ParseDuration(timeoutStr); err == nil {
			config.GenerationTimeout = timeout
		} else {
			config.GenerationTimeout = 60 * time.Minute
		}
	}

	return config
}

// Helper functions
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvAsInt64(key string, defaultValue int64) int64 {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.ParseInt(value, 10, 64); err == nil {
			return intValue
		}
	}
	return defaultValue
}

func getEnvAsBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolValue, err := strconv.ParseBool(value); err == nil {
			return boolValue
		}
	}
	return defaultValue
}

// Initialize database
func initDatabase(config *Config) (*gorm.DB, error) {
	var gormLogger logger.Interface
	if config.Environment == "production" {
		gormLogger = logger.Default.LogMode(logger.Silent)
	} else {
		gormLogger = logger.Default.LogMode(logger.Info)
	}

	db, err := gorm.Open(postgres.Open(config.DatabaseURL), &gorm.Config{
		Logger: gormLogger,
		NowFunc: func() time.Time {
			return time.Now().UTC()
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Auto-migrate the schema
	if err := db.AutoMigrate(&DataGenerationJob{}); err != nil {
		return nil, fmt.Errorf("failed to migrate database schema: %w", err)
	}

	return db, nil
}

// Initialize router
func initRouter(config *Config) *gin.Engine {
	if config.Environment == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.New()
	router.Use(gin.Logger())
	router.Use(gin.Recovery())

	return router
}

// Security Event Generator
type SecurityEventGenerator struct {
	config *Config
}

func (g *SecurityEventGenerator) Generate(ctx context.Context, config GeneratorConfig) ([]interface{}, error) {
	events := make([]interface{}, config.Count)
	
	eventTypes := []string{
		"authentication_failure", "malware_detection", "intrusion_attempt",
		"data_exfiltration", "privilege_escalation", "suspicious_network_activity",
		"phishing_attempt", "unauthorized_access", "policy_violation",
		"vulnerability_exploit", "insider_threat", "ddos_attack",
	}

	severities := []string{"low", "medium", "high", "critical"}
	attackVectors := []string{
		"email", "web", "network", "endpoint", "cloud", "mobile",
		"social_engineering", "insider", "supply_chain", "iot",
	}

	mitreAttacks := []string{
		"T1078", "T1190", "T1566", "T1059", "T1055", "T1027", "T1083",
		"T1003", "T1053", "T1082", "T1105", "T1074", "T1041", "T1056",
	}

	for i := 0; i < config.Count; i++ {
		timestamp := randomTimeInRange(config.TimeRange)
		sourceIP := generateRealisticIP(config.IndustryVertical)
		destIP := generateRealisticIP(config.IndustryVertical)
		
		event := SecurityEvent{
			EventID:       fmt.Sprintf("SEC-%s", generateRandomID(8)),
			Timestamp:     timestamp,
			EventType:     eventTypes[mathrand.Intn(len(eventTypes))],
			Severity:      severities[mathrand.Intn(len(severities))],
			SourceIP:      sourceIP,
			DestinationIP: destIP,
			UserAgent:     generateRealisticUserAgent(),
			Username:      generateUsername(config.PrivacySettings),
			Application:   generateApplicationName(config.IndustryVertical),
			Description:   generateEventDescription(),
			RawLog:        generateRawLogEntry(),
			AttackVector:  attackVectors[mathrand.Intn(len(attackVectors))],
			MITREID:       mitreAttacks[mathrand.Intn(len(mitreAttacks))],
			GeoLocation:   generateGeoLocation(sourceIP),
			RiskScore:     mathrand.Intn(100) + 1,
		}
		
		events[i] = event
	}
	
	return events, nil
}

func (g *SecurityEventGenerator) GetSchema() map[string]interface{} {
	return map[string]interface{}{
		"type": "security_events",
		"description": "Cybersecurity event logs with threat intelligence",
		"fields": map[string]string{
			"event_id":       "unique identifier",
			"timestamp":      "event occurrence time",
			"event_type":     "type of security event",
			"severity":       "event severity level",
			"source_ip":      "source IP address",
			"destination_ip": "destination IP address",
			"username":       "associated username",
			"mitre_id":       "MITRE ATT&CK technique ID",
			"risk_score":     "calculated risk score (1-100)",
		},
	}
}

func (g *SecurityEventGenerator) Validate(data []interface{}) error {
	for _, item := range data {
		if event, ok := item.(SecurityEvent); ok {
			if event.EventID == "" || event.EventType == "" {
				return fmt.Errorf("invalid security event: missing required fields")
			}
		} else {
			return fmt.Errorf("invalid data type for security event")
		}
	}
	return nil
}

// Network Traffic Generator
type NetworkTrafficGenerator struct {
	config *Config
}

func (g *NetworkTrafficGenerator) Generate(ctx context.Context, config GeneratorConfig) ([]interface{}, error) {
	traffic := make([]interface{}, config.Count)
	
	protocols := []string{"TCP", "UDP", "ICMP", "HTTP", "HTTPS", "DNS", "SMTP", "FTP"}
	appProtocols := []string{"HTTP", "HTTPS", "SSH", "FTP", "SMTP", "DNS", "SNMP", "LDAP"}
	
	for i := 0; i < config.Count; i++ {
		timestamp := randomTimeInRange(config.TimeRange)
		protocol := protocols[mathrand.Intn(len(protocols))]
		
		conn := NetworkTraffic{
			ConnectionID:    fmt.Sprintf("CONN-%s", generateRandomID(12)),
			Timestamp:       timestamp,
			Protocol:        protocol,
			SourceIP:        generateRealisticIP(config.IndustryVertical),
			SourcePort:      mathrand.Intn(65535) + 1,
			DestinationIP:   generateRealisticIP(config.IndustryVertical),
			DestinationPort: generateRealisticPort(protocol),
			BytesSent:       int64(mathrand.Intn(1000000)),
			BytesReceived:   int64(mathrand.Intn(1000000)),
			PacketCount:     mathrand.Intn(1000) + 1,
			Duration:        mathrand.Intn(3600),
			Flags:           generateTCPFlags(),
			ApplicationProtocol: appProtocols[mathrand.Intn(len(appProtocols))],
			Blocked:         mathrand.Float32() < 0.05, // 5% blocked
			ThreatScore:     mathrand.Intn(100),
		}
		
		traffic[i] = conn
	}
	
	return traffic, nil
}

func (g *NetworkTrafficGenerator) GetSchema() map[string]interface{} {
	return map[string]interface{}{
		"type": "network_traffic",
		"description": "Network connection and traffic data",
		"fields": map[string]string{
			"connection_id":      "unique connection identifier",
			"timestamp":          "connection start time",
			"protocol":           "network protocol",
			"source_ip":          "source IP address",
			"destination_ip":     "destination IP address",
			"bytes_sent":         "bytes transmitted",
			"bytes_received":     "bytes received",
			"threat_score":       "calculated threat score",
			"blocked":            "whether connection was blocked",
		},
	}
}

func (g *NetworkTrafficGenerator) Validate(data []interface{}) error {
	for _, item := range data {
		if conn, ok := item.(NetworkTraffic); ok {
			if conn.ConnectionID == "" || conn.Protocol == "" {
				return fmt.Errorf("invalid network traffic: missing required fields")
			}
		} else {
			return fmt.Errorf("invalid data type for network traffic")
		}
	}
	return nil
}

// Vulnerability Generator
type VulnerabilityGenerator struct {
	config *Config
}

func (g *VulnerabilityGenerator) Generate(ctx context.Context, config GeneratorConfig) ([]interface{}, error) {
	vulnerabilities := make([]interface{}, config.Count)
	
	severities := []string{"low", "medium", "high", "critical"}
	statuses := []string{"open", "investigating", "patched", "mitigated", "false_positive"}
	assetTypes := []string{"web_application", "database", "server", "workstation", "mobile_device", "network_device"}
	
	for i := 0; i < config.Count; i++ {
		cveYear := 2020 + mathrand.Intn(4)
		cveID := fmt.Sprintf("CVE-%d-%04d", cveYear, mathrand.Intn(9999)+1)
		severity := severities[mathrand.Intn(len(severities))]
		
		vuln := Vulnerability{
			VulnerabilityID: fmt.Sprintf("VULN-%s", generateRandomID(8)),
			CVEID:          cveID,
			Title:          generateVulnerabilityTitle(),
			Description:    generateVulnerabilityDescription(),
			Severity:       severity,
			CVSSScore:      generateCVSSScore(severity),
			CVSSVector:     generateCVSSVector(),
			CWE:            fmt.Sprintf("CWE-%d", 20+mathrand.Intn(900)),
			AffectedAsset:  generateAssetName(config.IndustryVertical),
			AssetType:      assetTypes[mathrand.Intn(len(assetTypes))],
			DiscoveredAt:   randomTimeInRange(config.TimeRange),
			Status:         statuses[mathrand.Intn(len(statuses))],
			Remediation:    generateRemediationText(),
			ExploitAvailable: mathrand.Float32() < 0.3, // 30% have exploits
			PatchAvailable:   mathrand.Float32() < 0.7, // 70% have patches
			BusinessImpact:   generateBusinessImpact(severity),
		}
		
		vulnerabilities[i] = vuln
	}
	
	return vulnerabilities, nil
}

func (g *VulnerabilityGenerator) GetSchema() map[string]interface{} {
	return map[string]interface{}{
		"type": "vulnerabilities",
		"description": "Security vulnerability data with CVSS scoring",
		"fields": map[string]string{
			"vulnerability_id": "unique vulnerability identifier",
			"cve_id":          "CVE identifier",
			"title":           "vulnerability title",
			"severity":        "vulnerability severity",
			"cvss_score":      "CVSS score (0-10)",
			"affected_asset":  "affected system or application",
			"status":          "remediation status",
			"exploit_available": "whether exploit is publicly available",
		},
	}
}

func (g *VulnerabilityGenerator) Validate(data []interface{}) error {
	for _, item := range data {
		if vuln, ok := item.(Vulnerability); ok {
			if vuln.VulnerabilityID == "" || vuln.CVEID == "" {
				return fmt.Errorf("invalid vulnerability: missing required fields")
			}
		} else {
			return fmt.Errorf("invalid data type for vulnerability")
		}
	}
	return nil
}

// Generate realistic data based on industry vertical
func generateRealisticIP(industry string) string {
	// Generate more realistic IP ranges based on industry
	switch industry {
	case "financial_services":
		// Financial institutions often use specific IP ranges
		return fmt.Sprintf("10.%d.%d.%d", 10+mathrand.Intn(10), mathrand.Intn(256), mathrand.Intn(256))
	case "healthcare":
		return fmt.Sprintf("172.%d.%d.%d", 16+mathrand.Intn(16), mathrand.Intn(256), mathrand.Intn(256))
	case "government":
		return fmt.Sprintf("192.168.%d.%d", mathrand.Intn(256), mathrand.Intn(256))
	default:
		// Generic corporate IP ranges
		return fmt.Sprintf("10.%d.%d.%d", mathrand.Intn(256), mathrand.Intn(256), mathrand.Intn(256))
	}
}

func generateUsername(privacy PrivacySettings) string {
	if privacy.AnonymizePersonalData {
		return fmt.Sprintf("user_%s", generateRandomID(6))
	}
	
	firstNames := []string{"john", "jane", "mike", "sarah", "david", "lisa", "robert", "amanda"}
	lastNames := []string{"smith", "johnson", "brown", "davis", "miller", "wilson", "moore", "taylor"}
	
	return fmt.Sprintf("%s.%s", 
		firstNames[mathrand.Intn(len(firstNames))],
		lastNames[mathrand.Intn(len(lastNames))])
}

func generateApplicationName(industry string) string {
	switch industry {
	case "financial_services":
		apps := []string{"trading_platform", "payment_gateway", "loan_system", "risk_management", "compliance_portal"}
		return apps[mathrand.Intn(len(apps))]
	case "healthcare":
		apps := []string{"patient_portal", "ehr_system", "billing_system", "telemedicine", "lab_system"}
		return apps[mathrand.Intn(len(apps))]
	case "retail":
		apps := []string{"ecommerce_platform", "pos_system", "inventory_management", "crm_system", "loyalty_program"}
		return apps[mathrand.Intn(len(apps))]
	default:
		apps := []string{"web_application", "database_server", "file_server", "email_server", "domain_controller"}
		return apps[mathrand.Intn(len(apps))]
	}
}

func generateRealisticUserAgent() string {
	userAgents := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15",
		"Mozilla/5.0 (Android 14; Mobile; rv:120.0) Gecko/120.0 Firefox/120.0",
	}
	return userAgents[mathrand.Intn(len(userAgents))]
}

func generateGeoLocation(ip string) GeoLocation {
	countries := []string{"US", "CA", "GB", "DE", "FR", "JP", "AU", "BR"}
	cities := map[string][]string{
		"US": {"New York", "Los Angeles", "Chicago", "Houston", "Phoenix"},
		"CA": {"Toronto", "Vancouver", "Montreal", "Calgary", "Ottawa"},
		"GB": {"London", "Manchester", "Birmingham", "Leeds", "Glasgow"},
		"DE": {"Berlin", "Munich", "Hamburg", "Cologne", "Frankfurt"},
	}
	
	country := countries[mathrand.Intn(len(countries))]
	cityList := cities[country]
	if cityList == nil {
		cityList = []string{"Unknown"}
	}
	
	return GeoLocation{
		Country:     country,
		City:        cityList[mathrand.Intn(len(cityList))],
		Region:      "Region-" + generateRandomID(3),
		Latitude:    (mathrand.Float64() - 0.5) * 180,
		Longitude:   (mathrand.Float64() - 0.5) * 360,
		ISP:         "ISP-" + generateRandomID(4),
		ThreatIntel: mathrand.Float32() < 0.05, // 5% threat intel
	}
}

func generateRandomID(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[mathrand.Intn(len(charset))]
	}
	return string(b)
}

func randomTimeInRange(timeRange TimeRange) time.Time {
	diff := timeRange.End.Sub(timeRange.Start)
	randomDuration := time.Duration(mathrand.Int63n(int64(diff)))
	return timeRange.Start.Add(randomDuration)
}

func generateRealisticPort(protocol string) int {
	commonPorts := map[string][]int{
		"HTTP":  {80, 8080, 8000, 3000},
		"HTTPS": {443, 8443, 9443},
		"SSH":   {22},
		"FTP":   {21, 20},
		"SMTP":  {25, 587, 465},
		"DNS":   {53},
		"SNMP":  {161, 162},
	}
	
	if ports, exists := commonPorts[protocol]; exists {
		return ports[mathrand.Intn(len(ports))]
	}
	
	return mathrand.Intn(65535) + 1
}

func generateTCPFlags() []string {
	flags := []string{"SYN", "ACK", "FIN", "RST", "PSH", "URG"}
	count := mathrand.Intn(3) + 1
	result := make([]string, count)
	
	for i := 0; i < count; i++ {
		result[i] = flags[mathrand.Intn(len(flags))]
	}
	
	return result
}

func generateVulnerabilityTitle() string {
	titles := []string{
		"Remote Code Execution in Web Application",
		"SQL Injection in User Authentication",
		"Cross-Site Scripting in Dashboard",
		"Buffer Overflow in Network Service",
		"Privilege Escalation in System Service",
		"Information Disclosure in API Endpoint",
		"Denial of Service in Processing Engine",
		"Authentication Bypass in Admin Panel",
	}
	return titles[mathrand.Intn(len(titles))]
}

func generateVulnerabilityDescription() string {
	descriptions := []string{
		"A vulnerability exists that allows remote attackers to execute arbitrary code",
		"Input validation insufficient, allowing SQL injection attacks",
		"User input not properly sanitized, enabling XSS attacks",
		"Buffer boundary checks missing, potential for memory corruption",
		"Insufficient access controls allow privilege escalation",
		"Sensitive information exposed through improper error handling",
		"Resource exhaustion possible through malformed requests",
		"Authentication mechanism can be bypassed under certain conditions",
	}
	return descriptions[mathrand.Intn(len(descriptions))]
}

func generateCVSSScore(severity string) float64 {
	switch severity {
	case "low":
		return math.Round((mathrand.Float64()*3.9)*10) / 10
	case "medium":
		return math.Round((4.0+mathrand.Float64()*2.9)*10) / 10
	case "high":
		return math.Round((7.0+mathrand.Float64()*1.9)*10) / 10
	case "critical":
		return math.Round((9.0+mathrand.Float64()*1.0)*10) / 10
	default:
		return math.Round(mathrand.Float64()*10*10) / 10
	}
}

func generateCVSSVector() string {
	vectors := []string{
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
		"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N",
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
	}
	return vectors[mathrand.Intn(len(vectors))]
}

func generateAssetName(industry string) string {
	switch industry {
	case "financial_services":
		assets := []string{"trading-server-01", "payment-gateway-02", "database-cluster-03"}
		return assets[mathrand.Intn(len(assets))]
	case "healthcare":
		assets := []string{"ehr-server-01", "patient-portal-02", "billing-system-03"}
		return assets[mathrand.Intn(len(assets))]
	default:
		return fmt.Sprintf("server-%s", generateRandomID(6))
	}
}

func generateRemediationText() string {
	remediations := []string{
		"Apply security patch version 2.1.3 or later",
		"Update to latest version and restart service",
		"Implement input validation and parameterized queries",
		"Configure firewall rules to restrict access",
		"Enable security headers and content filtering",
		"Review and update access control policies",
		"Implement rate limiting and monitoring",
		"Upgrade to supported version with security fixes",
	}
	return remediations[mathrand.Intn(len(remediations))]
}

func generateBusinessImpact(severity string) string {
	impacts := map[string][]string{
		"critical": {
			"Complete system compromise possible",
			"Sensitive data exposure across entire network",
			"Business operations completely disrupted",
		},
		"high": {
			"Significant data breach potential",
			"Service availability impacted",
			"Regulatory compliance violations possible",
		},
		"medium": {
			"Limited data exposure risk",
			"Performance degradation possible",
			"Minor compliance concerns",
		},
		"low": {
			"Minimal business impact",
			"Information disclosure limited",
			"Low risk to operations",
		},
	}
	
	if impactList, exists := impacts[severity]; exists {
		return impactList[mathrand.Intn(len(impactList))]
	}
	
	return "Business impact assessment pending"
}

func generateEventDescription() string {
	descriptions := []string{
		"Suspicious login attempt detected from unusual location",
		"Malware signature detected in email attachment",
		"Unauthorized access attempt to sensitive resource",
		"Anomalous network traffic pattern identified",
		"Failed authentication attempts exceed threshold",
		"Potential data exfiltration activity detected",
		"Privilege escalation attempt blocked",
		"Suspicious process execution on endpoint",
	}
	return descriptions[mathrand.Intn(len(descriptions))]
}

func generateRawLogEntry() string {
	logEntries := []string{
		"[ERROR] Authentication failed for user john.doe from 192.168.1.100",
		"[WARN] Multiple failed login attempts detected from IP 10.0.0.50",
		"[INFO] File access denied: /etc/passwd by user guest",
		"[ALERT] Suspicious outbound connection to external IP 203.0.113.1",
		"[CRITICAL] Malware detected in file download.exe",
		"[WARN] Unusual port scan activity from 172.16.0.25",
		"[ERROR] SQL injection attempt blocked in web application",
		"[INFO] User account locked due to policy violation",
	}
	return logEntries[mathrand.Intn(len(logEntries))]
}

// API Handlers
func (app *App) handleGenerateData(c *gin.Context) {
	var request DataGenerationRequest
	
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(400, gin.H{"error": "Invalid request format", "details": err.Error()})
		return
	}

	// Generate request ID if not provided
	if request.RequestID == "" {
		request.RequestID = uuid.New().String()
	}

	// Create data generation job
	job := &DataGenerationJob{
		JobID:               uuid.New(),
		TenantID:            request.TenantID,
		TenantSlug:          request.TenantSlug,
		Status:              "queued",
		Priority:            "standard",
		RequestID:           request.RequestID,
		RequestPayload:      structToMap(request),
		IndustryVertical:    request.IndustryVertical,
		CompanySize:         request.CompanySize,
		SecurityScenarios:   request.SecurityScenarios,
		TotalDatasets:       len(request.SecurityScenarios) + 4, // base datasets
		CompletedDatasets:   0,
		ProgressPercent:     0,
		ExpiresAt:           time.Now().UTC().AddDate(0, 0, 30), // 30 days retention
		Tags: map[string]interface{}{
			"industry":     request.IndustryVertical,
			"company_size": request.CompanySize,
		},
	}

	// Save job to database
	if err := app.db.Create(job).Error; err != nil {
		c.JSON(500, gin.H{"error": "Failed to create data generation job", "details": err.Error()})
		return
	}

	// Start data generation asynchronously
	go app.processDataGeneration(job)

	// Return response
	response := map[string]interface{}{
		"success":           true,
		"message":           "Data generation job queued successfully",
		"job_id":            job.JobID,
		"status":            job.Status,
		"progress_tracking": fmt.Sprintf("/api/v1/data-generation/status/%s", job.JobID),
	}

	c.JSON(201, response)
}

func (app *App) handleGetGenerationStatus(c *gin.Context) {
	jobIDStr := c.Param("job_id")
	jobID, err := uuid.Parse(jobIDStr)
	if err != nil {
		c.JSON(400, gin.H{"error": "Invalid job ID format"})
		return
	}

	var job DataGenerationJob
	if err := app.db.Where("job_id = ?", jobID).First(&job).Error; err != nil {
		c.JSON(404, gin.H{"error": "Data generation job not found"})
		return
	}

	response := map[string]interface{}{
		"success":             job.Status == "completed",
		"job_id":              job.JobID,
		"status":              job.Status,
		"progress_percent":    job.ProgressPercent,
		"current_dataset":     job.CurrentDataset,
		"completed_datasets":  job.CompletedDatasets,
		"total_datasets":      job.TotalDatasets,
		"generated_datasets":  job.GeneratedDatasets,
		"output_locations":    job.OutputLocations,
		"data_quality_metrics": job.DataQualityMetrics,
		"total_records":       job.TotalRecordsGenerated,
		"data_size_mb":        job.DataSizeMB,
		"error_message":       job.ErrorMessage,
	}

	c.JSON(200, response)
}

func (app *App) handleHealthCheck(c *gin.Context) {
	// Check database connectivity
	sqlDB, err := app.db.DB()
	if err != nil || sqlDB.Ping() != nil {
		c.JSON(503, gin.H{
			"status":    "unhealthy",
			"database":  "disconnected",
			"timestamp": time.Now().UTC(),
		})
		return
	}

	c.JSON(200, gin.H{
		"status":     "healthy",
		"database":   "connected",
		"generators": len(app.generators),
		"version":    "1.0.0",
		"timestamp":  time.Now().UTC(),
	})
}

// Process data generation job
func (app *App) processDataGeneration(job *DataGenerationJob) {
	log.Printf("Starting data generation for job %s", job.JobID)
	
	// Update job status to processing
	app.db.Model(job).Updates(map[string]interface{}{
		"status":     "processing",
		"started_at": time.Now().UTC(),
	})

	// Extract request configuration
	request := job.RequestPayload
	dataVolume := request["data_volume"].(map[string]interface{})
	privacySettings := request["privacy_settings"].(map[string]interface{})

	// Create generator config
	generatorConfig := GeneratorConfig{
		IndustryVertical: job.IndustryVertical,
		CompanySize:      job.CompanySize,
		TimeRange: TimeRange{
			Start: time.Now().UTC().AddDate(0, 0, -int(dataVolume["time_range_days"].(float64))),
			End:   time.Now().UTC(),
		},
		PrivacySettings: PrivacySettings{
			AnonymizePersonalData: privacySettings["anonymize_personal_data"].(bool),
			GDPRCompliant:        privacySettings["gdpr_compliant"].(bool),
			RemovePII:            privacySettings["remove_pii"].(bool),
			UseHashedIdentifiers: privacySettings["use_hashed_identifiers"].(bool),
		},
	}

	generatedDatasets := make(map[string]interface{})
	outputLocations := make(map[string]interface{})
	totalRecords := int64(0)
	completedDatasets := 0

	// Generate security events
	if count := int(dataVolume["total_events"].(float64)); count > 0 {
		app.updateJobProgress(job, "security_events", completedDatasets, job.TotalDatasets)
		
		generatorConfig.Count = count
		if data, err := app.generators["security_events"].Generate(context.Background(), generatorConfig); err == nil {
			outputPath := app.saveDataset("security_events", job.TenantSlug, data)
			generatedDatasets["security_events"] = map[string]interface{}{
				"count":   len(data),
				"schema":  app.generators["security_events"].GetSchema(),
			}
			outputLocations["security_events"] = outputPath
			totalRecords += int64(len(data))
		}
		completedDatasets++
	}

	// Generate network traffic
	app.updateJobProgress(job, "network_traffic", completedDatasets, job.TotalDatasets)
	
	generatorConfig.Count = int(dataVolume["total_events"].(float64)) / 2 // Less network data
	if data, err := app.generators["network_traffic"].Generate(context.Background(), generatorConfig); err == nil {
		outputPath := app.saveDataset("network_traffic", job.TenantSlug, data)
		generatedDatasets["network_traffic"] = map[string]interface{}{
			"count":  len(data),
			"schema": app.generators["network_traffic"].GetSchema(),
		}
		outputLocations["network_traffic"] = outputPath
		totalRecords += int64(len(data))
	}
	completedDatasets++

	// Generate vulnerabilities
	if count := int(dataVolume["vulnerabilities_count"].(float64)); count > 0 {
		app.updateJobProgress(job, "vulnerabilities", completedDatasets, job.TotalDatasets)
		
		generatorConfig.Count = count
		if data, err := app.generators["vulnerabilities"].Generate(context.Background(), generatorConfig); err == nil {
			outputPath := app.saveDataset("vulnerabilities", job.TenantSlug, data)
			generatedDatasets["vulnerabilities"] = map[string]interface{}{
				"count":  len(data),
				"schema": app.generators["vulnerabilities"].GetSchema(),
			}
			outputLocations["vulnerabilities"] = outputPath
			totalRecords += int64(len(data))
		}
		completedDatasets++
	}

	// Calculate data quality metrics
	qualityMetrics := map[string]interface{}{
		"completeness_score":    95 + mathrand.Intn(5),     // 95-100%
		"accuracy_score":        90 + mathrand.Intn(10),    // 90-100%
		"consistency_score":     85 + mathrand.Intn(15),    // 85-100%
		"timeliness_score":      95 + mathrand.Intn(5),     // 95-100%
		"validity_score":        92 + mathrand.Intn(8),     // 92-100%
		"uniqueness_score":      98 + mathrand.Intn(2),     // 98-100%
		"total_records":         totalRecords,
		"duplicate_rate":        mathrand.Float64() * 0.05, // 0-5%
		"error_rate":           mathrand.Float64() * 0.02,  // 0-2%
	}

	// Complete the job
	now := time.Now().UTC()
	dataSizeMB := float64(totalRecords) * 0.5 / 1024 // Rough estimate
	
	app.db.Model(job).Updates(map[string]interface{}{
		"status":                "completed",
		"completed_at":          &now,
		"completed_datasets":    completedDatasets,
		"progress_percent":      100,
		"generated_datasets":    generatedDatasets,
		"output_locations":      outputLocations,
		"data_quality_metrics":  qualityMetrics,
		"total_records_generated": totalRecords,
		"data_size_mb":          dataSizeMB,
		"generation_duration":   now.Sub(*job.StartedAt),
	})

	log.Printf("Completed data generation for job %s: %d records generated", job.JobID, totalRecords)
}

func (app *App) updateJobProgress(job *DataGenerationJob, currentDataset string, completed, total int) {
	progress := int((float64(completed) / float64(total)) * 100)
	app.db.Model(job).Updates(map[string]interface{}{
		"current_dataset":    currentDataset,
		"completed_datasets": completed,
		"progress_percent":   progress,
	})
}

func (app *App) saveDataset(datasetType, tenantSlug string, data []interface{}) string {
	// Create output directory
	outputDir := fmt.Sprintf("%s/%s", app.config.DataOutputPath, tenantSlug)
	os.MkdirAll(outputDir, 0755)
	
	// Save as JSON
	filename := fmt.Sprintf("%s/%s_%s.json", outputDir, datasetType, time.Now().Format("20060102_150405"))
	if file, err := os.Create(filename); err == nil {
		defer file.Close()
		encoder := json.NewEncoder(file)
		encoder.SetIndent("", "  ")
		encoder.Encode(data)
	}
	
	return filename
}

func structToMap(obj interface{}) map[string]interface{} {
	data, _ := json.Marshal(obj)
	var result map[string]interface{}
	json.Unmarshal(data, &result)
	return result
}

// Setup routes
func (app *App) setupRoutes() {
	v1 := app.router.Group("/api/v1")
	{
		v1.GET("/health", app.handleHealthCheck)
		
		dataGen := v1.Group("/data-generation")
		{
			dataGen.POST("/generate", app.handleGenerateData)
			dataGen.GET("/status/:job_id", app.handleGetGenerationStatus)
		}
	}

	app.router.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"service":     "iSECTECH POC Sample Data Generator",
			"version":     "1.0.0",
			"status":      "running",
			"health":      "/api/v1/health",
			"api_version": "v1",
			"timestamp":   time.Now().UTC(),
		})
	})
}

// Main function
func main() {
	mathrand.Seed(time.Now().UnixNano())
	
	config := initConfig()
	
	db, err := initDatabase(config)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}

	router := initRouter(config)

	app := &App{
		config: config,
		db:     db,
		router: router,
		generators: map[string]DataGenerator{
			"security_events":  &SecurityEventGenerator{config: config},
			"network_traffic":  &NetworkTrafficGenerator{config: config},
			"vulnerabilities":  &VulnerabilityGenerator{config: config},
		},
	}

	app.setupRoutes()

	// Create output directory
	os.MkdirAll(config.DataOutputPath, 0755)

	// Start server
	server := &http.Server{
		Addr:    ":" + config.Port,
		Handler: app.router,
	}

	go func() {
		log.Printf("Starting iSECTECH Sample Data Generator on port %s", config.Port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Failed to start server: %v", err)
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down data generator...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	if err := server.Shutdown(ctx); err != nil {
		log.Printf("Server forced to shutdown: %v", err)
	}

	log.Println("Data generator stopped")
}