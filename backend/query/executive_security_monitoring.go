package query

import (
	"context"
	"fmt"
	"math"
	"net"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// ExecutiveThreatMonitor monitors threats specifically for executive users
type ExecutiveThreatMonitor struct {
	logger            *zap.Logger
	config            *ExecutiveMonitoringConfig
	threatIntelFeed   ThreatIntelligenceFeed
	behaviorBaseline  map[string]*UserBehaviorBaseline
	baselineMutex     sync.RWMutex
	riskPatterns      map[string]float64
	ipReputation      map[string]float64
	geoRisk           map[string]float64
}

// ExecutiveAnomalyDetector detects behavioral anomalies for executive users
type ExecutiveAnomalyDetector struct {
	logger            *zap.Logger
	config            *ExecutiveMonitoringConfig
	userProfiles      map[string]*ExecutiveUserProfile
	profileMutex      sync.RWMutex
	anomalyThreshold  float64
	timeWindows       []time.Duration
	featureWeights    map[string]float64
}

// Supporting data structures
type UserBehaviorBaseline struct {
	UserID                string                    `json:"user_id"`
	TypicalLoginTimes     []BehaviorTimeRange       `json:"typical_login_times"`
	TypicalLocations      []LocationPattern         `json:"typical_locations"`
	TypicalDevices        []DevicePattern           `json:"typical_devices"`
	TypicalAccessPatterns map[string]AccessPattern  `json:"typical_access_patterns"`
	DataAccessVolume      VolumeBaseline            `json:"data_access_volume"`
	SessionDuration       DurationBaseline          `json:"session_duration"`
	CreatedAt             time.Time                 `json:"created_at"`
	UpdatedAt             time.Time                 `json:"updated_at"`
	SampleSize            int                       `json:"sample_size"`
	Confidence            float64                   `json:"confidence"`
}

type ExecutiveUserProfile struct {
	UserID              string                    `json:"user_id"`
	Role                string                    `json:"role"`
	SecurityClearance   string                    `json:"security_clearance"`
	TypicalBehavior     *UserBehaviorBaseline     `json:"typical_behavior"`
	RecentActivity      []*ActivityRecord         `json:"recent_activity"`
	RiskProfile         *ExecutiveRiskProfile     `json:"risk_profile"`
	AnomalyHistory      []*AnomalyRecord          `json:"anomaly_history"`
	LastProfileUpdate   time.Time                 `json:"last_profile_update"`
	ProfileVersion      int                       `json:"profile_version"`
}

type ExecutiveRiskProfile struct {
	BaselineRiskScore    float64                  `json:"baseline_risk_score"`
	ThreatExposure       float64                  `json:"threat_exposure"`
	AccessPrivileges     []string                 `json:"access_privileges"`
	DataSensitivity      float64                  `json:"data_sensitivity"`
	GeographicRisk       float64                  `json:"geographic_risk"`
	DeviceRisk           float64                  `json:"device_risk"`
	NetworkRisk          float64                  `json:"network_risk"`
	BehavioralRisk       float64                  `json:"behavioral_risk"`
	ComplianceRequirements []string               `json:"compliance_requirements"`
	LastAssessed         time.Time                `json:"last_assessed"`
}

type BehaviorTimeRange struct {
	StartTime time.Time `json:"start_time"`
	EndTime   time.Time `json:"end_time"`
	DayOfWeek int       `json:"day_of_week"`
	Frequency float64   `json:"frequency"`
}

type LocationPattern struct {
	Country     string  `json:"country"`
	Region      string  `json:"region"`
	City        string  `json:"city"`
	Latitude    float64 `json:"latitude"`
	Longitude   float64 `json:"longitude"`
	Radius      float64 `json:"radius_km"`
	Frequency   float64 `json:"frequency"`
	RiskScore   float64 `json:"risk_score"`
}

type DevicePattern struct {
	DeviceID          string            `json:"device_id"`
	DeviceType        string            `json:"device_type"`
	OperatingSystem   string            `json:"operating_system"`
	UserAgent         string            `json:"user_agent"`
	TrustScore        float64           `json:"trust_score"`
	LastSeen          time.Time         `json:"last_seen"`
	Frequency         float64           `json:"frequency"`
	SecurityFeatures  map[string]bool   `json:"security_features"`
}

type AccessPattern struct {
	Resource       string    `json:"resource"`
	Action         string    `json:"action"`
	TypicalTimes   []BehaviorTimeRange `json:"typical_times"`
	Frequency      float64   `json:"frequency"`
	DataVolume     float64   `json:"data_volume"`
	Duration       time.Duration `json:"duration"`
	AccessMethod   string    `json:"access_method"`
}

type VolumeBaseline struct {
	AverageVolume     float64           `json:"average_volume"`
	MedianVolume      float64           `json:"median_volume"`
	MaxVolume         float64           `json:"max_volume"`
	StandardDeviation float64           `json:"standard_deviation"`
	VolumeByResource  map[string]float64 `json:"volume_by_resource"`
}

type DurationBaseline struct {
	AverageDuration   time.Duration     `json:"average_duration"`
	MedianDuration    time.Duration     `json:"median_duration"`
	MaxDuration       time.Duration     `json:"max_duration"`
	StandardDeviation time.Duration     `json:"standard_deviation"`
}

type ActivityRecord struct {
	Timestamp         time.Time                 `json:"timestamp"`
	Resource          string                    `json:"resource"`
	Action            string                    `json:"action"`
	IPAddress         string                    `json:"ip_address"`
	Location          *SessionLocation          `json:"location"`
	DeviceID          string                    `json:"device_id"`
	Duration          time.Duration             `json:"duration"`
	DataVolume        int64                     `json:"data_volume"`
	Success           bool                      `json:"success"`
	AnomalyScore      float64                   `json:"anomaly_score"`
	Context           map[string]interface{}    `json:"context"`
}

type AnomalyRecord struct {
	ID               string                    `json:"id"`
	Type             string                    `json:"type"`
	Severity         string                    `json:"severity"`
	Score            float64                   `json:"score"`
	Description      string                    `json:"description"`
	DetectedAt       time.Time                 `json:"detected_at"`
	Features         map[string]float64        `json:"features"`
	Context          map[string]interface{}    `json:"context"`
	Resolved         bool                      `json:"resolved"`
	ResolvedAt       *time.Time                `json:"resolved_at,omitempty"`
	FalsePositive    bool                      `json:"false_positive"`
}

// Interface definitions
type ThreatIntelligenceFeed interface {
	GetIPReputation(ctx context.Context, ip string) (*IPReputationInfo, error)
	GetCountryRisk(ctx context.Context, country string) (*CountryRiskInfo, error)
	GetThreatIndicators(ctx context.Context, indicators []string) ([]*ThreatIndicator, error)
	IsKnownMaliciousIP(ctx context.Context, ip string) (bool, error)
}

type IPReputationInfo struct {
	IP               string    `json:"ip"`
	ReputationScore  float64   `json:"reputation_score"`
	Categories       []string  `json:"categories"`
	FirstSeen        time.Time `json:"first_seen"`
	LastSeen         time.Time `json:"last_seen"`
	ConfidenceLevel  float64   `json:"confidence_level"`
	Sources          []string  `json:"sources"`
}

type CountryRiskInfo struct {
	Country         string  `json:"country"`
	RiskScore       float64 `json:"risk_score"`
	RiskCategory    string  `json:"risk_category"`
	Factors         []string `json:"factors"`
	LastUpdated     time.Time `json:"last_updated"`
}

type ThreatIndicator struct {
	Type            string                 `json:"type"`
	Value           string                 `json:"value"`
	Severity        string                 `json:"severity"`
	Confidence      float64                `json:"confidence"`
	Description     string                 `json:"description"`
	Sources         []string               `json:"sources"`
	Context         map[string]interface{} `json:"context"`
	FirstSeen       time.Time              `json:"first_seen"`
	LastSeen        time.Time              `json:"last_seen"`
}

// Supporting types for security controls
type CreateSessionRequest struct {
	UserID            string               `json:"user_id"`
	UserRole          string               `json:"user_role"`
	TenantID          string               `json:"tenant_id"`
	AuthMethods       []string             `json:"auth_methods"`
	SecurityClearance string               `json:"security_clearance"`
	IPAddress         string               `json:"ip_address"`
	UserAgent         string               `json:"user_agent"`
	DeviceID          string               `json:"device_id,omitempty"`
	Location          *SessionLocation     `json:"location,omitempty"`
	RequestedDuration *time.Duration       `json:"requested_duration,omitempty"`
}

type SessionUpdate struct {
	LastActivity         *time.Time       `json:"last_activity,omitempty"`
	Location             *SessionLocation `json:"location,omitempty"`
	ThreatScore          *float64         `json:"threat_score,omitempty"`
	AnomalyScore         *float64         `json:"anomaly_score,omitempty"`
	ContinuousAuthScore  *float64         `json:"continuous_auth_score,omitempty"`
}

type MFAChallenge struct {
	ChallengeID    string            `json:"challenge_id"`
	UserID         string            `json:"user_id"`
	RequiredFactors []string         `json:"required_factors"`
	Challenges     map[string]string `json:"challenges"`
	ExpiresAt      time.Time         `json:"expires_at"`
	Attempts       int               `json:"attempts"`
	MaxAttempts    int               `json:"max_attempts"`
}

type MFAResult struct {
	Success        bool              `json:"success"`
	FactorsPassed  []string          `json:"factors_passed"`
	FactorsFailed  []string          `json:"factors_failed"`
	Score          float64           `json:"score"`
	NextChallenge  *MFAChallenge     `json:"next_challenge,omitempty"`
	Reason         string            `json:"reason,omitempty"`
}

type MFAStatus struct {
	UserID         string            `json:"user_id"`
	RequiredFactors []string         `json:"required_factors"`
	ConfiguredFactors []string       `json:"configured_factors"`
	RecentAttempts int               `json:"recent_attempts"`
	LastSuccess    *time.Time        `json:"last_success,omitempty"`
	IsLocked       bool              `json:"is_locked"`
	UnlockAt       *time.Time        `json:"unlock_at,omitempty"`
}

// NewExecutiveThreatMonitor creates a new executive threat monitor
func NewExecutiveThreatMonitor(logger *zap.Logger, config *ExecutiveMonitoringConfig) *ExecutiveThreatMonitor {
	monitor := &ExecutiveThreatMonitor{
		logger:           logger.With(zap.String("component", "executive-threat-monitor")),
		config:           config,
		behaviorBaseline: make(map[string]*UserBehaviorBaseline),
		riskPatterns:     make(map[string]float64),
		ipReputation:     make(map[string]float64),
		geoRisk:         make(map[string]float64),
	}
	
	// Initialize risk patterns
	monitor.initializeRiskPatterns()
	
	return monitor
}

// NewExecutiveAnomalyDetector creates a new executive anomaly detector
func NewExecutiveAnomalyDetector(logger *zap.Logger, config *ExecutiveMonitoringConfig) *ExecutiveAnomalyDetector {
	detector := &ExecutiveAnomalyDetector{
		logger:           logger.With(zap.String("component", "executive-anomaly-detector")),
		config:           config,
		userProfiles:     make(map[string]*ExecutiveUserProfile),
		anomalyThreshold: 0.7, // Configurable threshold
		timeWindows:      []time.Duration{1 * time.Hour, 24 * time.Hour, 7 * 24 * time.Hour},
		featureWeights:   make(map[string]float64),
	}
	
	// Initialize feature weights
	detector.initializeFeatureWeights()
	
	return detector
}

// AssessRequest assesses threat level for an access request
func (etm *ExecutiveThreatMonitor) AssessRequest(ctx context.Context, req *ExecutiveAccessRequest) float64 {
	var threatScore float64
	
	// IP-based threat assessment
	if ipScore := etm.assessIPThreat(req.IPAddress); ipScore > 0 {
		threatScore += ipScore * 0.3
	}
	
	// Location-based threat assessment
	if req.Location != nil {
		if geoScore := etm.assessGeographicThreat(req.Location); geoScore > 0 {
			threatScore += geoScore * 0.2
		}
	}
	
	// Time-based threat assessment
	if timeScore := etm.assessTimeBasedThreat(req.UserID, req.RequestedAt); timeScore > 0 {
		threatScore += timeScore * 0.2
	}
	
	// Access pattern threat assessment
	if patternScore := etm.assessAccessPatternThreat(req); patternScore > 0 {
		threatScore += patternScore * 0.3
	}
	
	// Normalize score to 0-1 range
	threatScore = math.Min(threatScore, 1.0)
	
	etm.logger.Debug("Threat assessment completed",
		zap.String("user_id", req.UserID.String()),
		zap.String("resource", req.Resource),
		zap.Float64("threat_score", threatScore),
		zap.String("ip_address", req.IPAddress),
	)
	
	return threatScore
}

// ScoreSession assesses ongoing threat level for an active session
func (etm *ExecutiveThreatMonitor) ScoreSession(ctx context.Context, session *ExecutiveSession) float64 {
	var threatScore float64
	
	// Check for session hijacking indicators
	if hijackScore := etm.assessSessionHijackingRisk(session); hijackScore > 0 {
		threatScore += hijackScore * 0.4
	}
	
	// Check for concurrent suspicious activities
	if concurrentScore := etm.assessConcurrentActivities(session); concurrentScore > 0 {
		threatScore += concurrentScore * 0.3
	}
	
	// Check for privilege escalation attempts
	if escalationScore := etm.assessPrivilegeEscalation(session); escalationScore > 0 {
		threatScore += escalationScore * 0.3
	}
	
	// Normalize score
	threatScore = math.Min(threatScore, 1.0)
	
	return threatScore
}

// ScoreRequest detects anomalies in an access request
func (ead *ExecutiveAnomalyDetector) ScoreRequest(ctx context.Context, req *ExecutiveAccessRequest) float64 {
	userID := req.UserID.String()
	
	// Get or create user profile
	ead.profileMutex.RLock()
	profile, exists := ead.userProfiles[userID]
	ead.profileMutex.RUnlock()
	
	if !exists {
		// Create new profile and return low anomaly score for new users
		ead.createUserProfile(userID, req)
		return 0.1
	}
	
	var anomalyScore float64
	
	// Time-based anomaly detection
	if timeAnomaly := ead.detectTimeAnomaly(req, profile); timeAnomaly > 0 {
		anomalyScore += timeAnomaly * ead.featureWeights["time"]
	}
	
	// Location-based anomaly detection
	if req.Location != nil {
		if locationAnomaly := ead.detectLocationAnomaly(req.Location, profile); locationAnomaly > 0 {
			anomalyScore += locationAnomaly * ead.featureWeights["location"]
		}
	}
	
	// Access pattern anomaly detection
	if patternAnomaly := ead.detectAccessPatternAnomaly(req, profile); patternAnomaly > 0 {
		anomalyScore += patternAnomaly * ead.featureWeights["access_pattern"]
	}
	
	// Device anomaly detection
	if deviceAnomaly := ead.detectDeviceAnomaly(req, profile); deviceAnomaly > 0 {
		anomalyScore += deviceAnomaly * ead.featureWeights["device"]
	}
	
	// Update profile with new activity
	ead.updateUserProfile(userID, req, anomalyScore)
	
	// Normalize score
	anomalyScore = math.Min(anomalyScore, 1.0)
	
	ead.logger.Debug("Anomaly detection completed",
		zap.String("user_id", userID),
		zap.Float64("anomaly_score", anomalyScore),
	)
	
	return anomalyScore
}

// ScoreSession detects anomalies in an active session
func (ead *ExecutiveAnomalyDetector) ScoreSession(ctx context.Context, session *ExecutiveSession) float64 {
	userID := session.UserID.String()
	
	ead.profileMutex.RLock()
	profile, exists := ead.userProfiles[userID]
	ead.profileMutex.RUnlock()
	
	if !exists {
		return 0.1 // Low score for unknown sessions
	}
	
	var anomalyScore float64
	
	// Session duration anomaly
	if durationAnomaly := ead.detectSessionDurationAnomaly(session, profile); durationAnomaly > 0 {
		anomalyScore += durationAnomaly * ead.featureWeights["session_duration"]
	}
	
	// Data access volume anomaly
	if volumeAnomaly := ead.detectDataVolumeAnomaly(session, profile); volumeAnomaly > 0 {
		anomalyScore += volumeAnomaly * ead.featureWeights["data_volume"]
	}
	
	// Activity frequency anomaly
	if frequencyAnomaly := ead.detectActivityFrequencyAnomaly(session, profile); frequencyAnomaly > 0 {
		anomalyScore += frequencyAnomaly * ead.featureWeights["activity_frequency"]
	}
	
	// Normalize score
	anomalyScore = math.Min(anomalyScore, 1.0)
	
	return anomalyScore
}

// Private helper methods for threat monitoring
func (etm *ExecutiveThreatMonitor) initializeRiskPatterns() {
	etm.riskPatterns = map[string]float64{
		"tor_exit_node":          0.8,
		"known_proxy":            0.6,
		"vpn_service":           0.4,
		"datacenter_ip":         0.3,
		"high_risk_country":     0.7,
		"unusual_time_access":   0.5,
		"multiple_failed_attempts": 0.9,
		"privilege_escalation":  0.9,
		"bulk_data_access":      0.7,
	}
	
	// Initialize geographic risk scores
	etm.geoRisk = map[string]float64{
		"high_risk_countries": 0.8,
		"medium_risk_countries": 0.5,
		"low_risk_countries": 0.1,
	}
}

func (etm *ExecutiveThreatMonitor) assessIPThreat(ipAddress string) float64 {
	// Check if IP is in known threat lists
	if score, exists := etm.ipReputation[ipAddress]; exists {
		return score
	}
	
	// Check IP characteristics
	ip := net.ParseIP(ipAddress)
	if ip == nil {
		return 0.5 // Invalid IP format is suspicious
	}
	
	// Check if IP is from a datacenter or cloud provider
	if etm.isDatacenterIP(ip) {
		return 0.3
	}
	
	// Check if IP is a known proxy/VPN
	if etm.isProxyOrVPN(ip) {
		return 0.6
	}
	
	return 0.0 // Clean IP
}

func (etm *ExecutiveThreatMonitor) assessGeographicThreat(location *SessionLocation) float64 {
	// Check country risk
	countryRisk := etm.getCountryRisk(location.Country)
	
	// Check for location jumping (would require session history)
	locationJumpRisk := 0.0 // Placeholder
	
	return math.Max(countryRisk, locationJumpRisk)
}

func (etm *ExecutiveThreatMonitor) assessTimeBasedThreat(userID UUID, requestTime time.Time) float64 {
	// Check if access is outside normal business hours
	hour := requestTime.Hour()
	if hour < 6 || hour > 22 { // Outside 6 AM - 10 PM
		return 0.3
	}
	
	// Check if access is on weekend
	weekday := requestTime.Weekday()
	if weekday == time.Saturday || weekday == time.Sunday {
		return 0.2
	}
	
	return 0.0
}

func (etm *ExecutiveThreatMonitor) assessAccessPatternThreat(req *ExecutiveAccessRequest) float64 {
	var threatScore float64
	
	// Check for bulk data access
	if strings.Contains(req.Resource, "bulk") || req.Action == "export" {
		threatScore += 0.4
	}
	
	// Check for administrative actions
	if strings.Contains(req.Action, "admin") || strings.Contains(req.Action, "delete") {
		threatScore += 0.3
	}
	
	// Check urgency level - high urgency could be suspicious
	if req.UrgencyLevel == "emergency" || req.UrgencyLevel == "critical" {
		threatScore += 0.2
	}
	
	return threatScore
}

func (etm *ExecutiveThreatMonitor) assessSessionHijackingRisk(session *ExecutiveSession) float64 {
	// Check for sudden changes in session characteristics
	// This would require comparing current session state with historical data
	return 0.0 // Placeholder implementation
}

func (etm *ExecutiveThreatMonitor) assessConcurrentActivities(session *ExecutiveSession) float64 {
	// Check for suspicious concurrent activities
	// This would analyze current session activities for suspicious patterns
	return 0.0 // Placeholder implementation
}

func (etm *ExecutiveThreatMonitor) assessPrivilegeEscalation(session *ExecutiveSession) float64 {
	// Check for attempts to access resources beyond normal privileges
	// This would compare current access requests with historical patterns
	return 0.0 // Placeholder implementation
}

func (etm *ExecutiveThreatMonitor) isDatacenterIP(ip net.IP) bool {
	// Simplified datacenter detection
	// In production, this would use comprehensive IP geolocation databases
	return false
}

func (etm *ExecutiveThreatMonitor) isProxyOrVPN(ip net.IP) bool {
	// Simplified proxy/VPN detection
	// In production, this would use threat intelligence feeds
	return false
}

func (etm *ExecutiveThreatMonitor) getCountryRisk(country string) float64 {
	// High-risk countries (example list)
	highRiskCountries := []string{"CN", "RU", "IR", "KP", "XX"}
	for _, riskCountry := range highRiskCountries {
		if country == riskCountry {
			return 0.8
		}
	}
	return 0.1
}

// Private helper methods for anomaly detection
func (ead *ExecutiveAnomalyDetector) initializeFeatureWeights() {
	ead.featureWeights = map[string]float64{
		"time":               0.25,
		"location":           0.20,
		"access_pattern":     0.20,
		"device":            0.15,
		"session_duration":  0.10,
		"data_volume":       0.05,
		"activity_frequency": 0.05,
	}
}

func (ead *ExecutiveAnomalyDetector) createUserProfile(userID string, req *ExecutiveAccessRequest) {
	profile := &ExecutiveUserProfile{
		UserID:              userID,
		Role:                req.ExecutiveRole,
		SecurityClearance:   req.SecurityClearance,
		RecentActivity:      make([]*ActivityRecord, 0),
		AnomalyHistory:      make([]*AnomalyRecord, 0),
		LastProfileUpdate:   time.Now(),
		ProfileVersion:      1,
	}
	
	ead.profileMutex.Lock()
	ead.userProfiles[userID] = profile
	ead.profileMutex.Unlock()
	
	ead.logger.Info("Created new user profile for anomaly detection",
		zap.String("user_id", userID),
		zap.String("role", req.ExecutiveRole),
	)
}

func (ead *ExecutiveAnomalyDetector) detectTimeAnomaly(req *ExecutiveAccessRequest, profile *ExecutiveUserProfile) float64 {
	if profile.TypicalBehavior == nil {
		return 0.0 // No baseline yet
	}
	
	currentTime := req.RequestedAt
	currentHour := currentTime.Hour()
	currentDay := int(currentTime.Weekday())
	
	// Check against typical login times
	for _, behaviorTimeRange := range profile.TypicalBehavior.TypicalLoginTimes {
		if behaviorTimeRange.DayOfWeek == currentDay {
			startHour := behaviorTimeRange.StartTime.Hour()
			endHour := behaviorTimeRange.EndTime.Hour()
			
			if currentHour >= startHour && currentHour <= endHour {
				return 0.0 // Normal time
			}
		}
	}
	
	// Calculate anomaly score based on how far from typical times
	return 0.5 // Simplified calculation
}

func (ead *ExecutiveAnomalyDetector) detectLocationAnomaly(location *SessionLocation, profile *ExecutiveUserProfile) float64 {
	if profile.TypicalBehavior == nil || len(profile.TypicalBehavior.TypicalLocations) == 0 {
		return 0.0
	}
	
	// Calculate distance from typical locations
	minDistance := math.Inf(1)
	for _, typicalLocation := range profile.TypicalBehavior.TypicalLocations {
		distance := ead.calculateDistance(
			location.Latitude, location.Longitude,
			typicalLocation.Latitude, typicalLocation.Longitude,
		)
		if distance < minDistance {
			minDistance = distance
		}
	}
	
	// Convert distance to anomaly score
	if minDistance > 1000 { // More than 1000km from typical locations
		return 0.8
	} else if minDistance > 100 { // More than 100km
		return 0.5
	} else if minDistance > 10 { // More than 10km
		return 0.2
	}
	
	return 0.0
}

func (ead *ExecutiveAnomalyDetector) detectAccessPatternAnomaly(req *ExecutiveAccessRequest, profile *ExecutiveUserProfile) float64 {
	if profile.TypicalBehavior == nil {
		return 0.0
	}
	
	// Check if resource access is typical
	accessPattern, exists := profile.TypicalBehavior.TypicalAccessPatterns[req.Resource]
	if !exists {
		return 0.3 // New resource access is somewhat anomalous
	}
	
	// Check if action is typical for this resource
	// This would be more sophisticated in production
	if accessPattern.Frequency < 0.1 {
		return 0.4 // Rarely accessed resource
	}
	
	return 0.0
}

func (ead *ExecutiveAnomalyDetector) detectDeviceAnomaly(req *ExecutiveAccessRequest, profile *ExecutiveUserProfile) float64 {
	if profile.TypicalBehavior == nil || len(profile.TypicalBehavior.TypicalDevices) == 0 {
		return 0.2 // New device
	}
	
	// Check if device is known
	for _, device := range profile.TypicalBehavior.TypicalDevices {
		if device.DeviceID == req.DeviceID {
			return 0.0 // Known device
		}
		if device.UserAgent == req.UserAgent {
			return 0.1 // Same browser/client
		}
	}
	
	return 0.3 // Unknown device
}

func (ead *ExecutiveAnomalyDetector) detectSessionDurationAnomaly(session *ExecutiveSession, profile *ExecutiveUserProfile) float64 {
	if profile.TypicalBehavior == nil {
		return 0.0
	}
	
	currentDuration := time.Since(session.CreatedAt)
	avgDuration := profile.TypicalBehavior.SessionDuration.AverageDuration
	
	if avgDuration == 0 {
		return 0.0 // No baseline
	}
	
	ratio := float64(currentDuration) / float64(avgDuration)
	if ratio > 3.0 { // Session is 3x longer than average
		return 0.6
	} else if ratio > 2.0 { // 2x longer
		return 0.3
	}
	
	return 0.0
}

func (ead *ExecutiveAnomalyDetector) detectDataVolumeAnomaly(session *ExecutiveSession, profile *ExecutiveUserProfile) float64 {
	// This would analyze data access volume in current session vs baseline
	// Placeholder implementation
	return 0.0
}

func (ead *ExecutiveAnomalyDetector) detectActivityFrequencyAnomaly(session *ExecutiveSession, profile *ExecutiveUserProfile) float64 {
	// This would analyze activity frequency patterns
	// Placeholder implementation
	return 0.0
}

func (ead *ExecutiveAnomalyDetector) updateUserProfile(userID string, req *ExecutiveAccessRequest, anomalyScore float64) {
	ead.profileMutex.Lock()
	defer ead.profileMutex.Unlock()
	
	profile := ead.userProfiles[userID]
	if profile == nil {
		return
	}
	
	// Add activity record
	activity := &ActivityRecord{
		Timestamp:    req.RequestedAt,
		Resource:     req.Resource,
		Action:       req.Action,
		IPAddress:    req.IPAddress,
		Location:     req.Location,
		DeviceID:     req.DeviceID,
		Success:      true, // Would be updated based on actual outcome
		AnomalyScore: anomalyScore,
		Context:      map[string]interface{}{"executive_role": req.ExecutiveRole},
	}
	
	profile.RecentActivity = append(profile.RecentActivity, activity)
	
	// Keep only recent activities (last 1000)
	if len(profile.RecentActivity) > 1000 {
		profile.RecentActivity = profile.RecentActivity[len(profile.RecentActivity)-1000:]
	}
	
	// Create anomaly record if score is high
	if anomalyScore > ead.anomalyThreshold {
		anomaly := &AnomalyRecord{
			ID:          fmt.Sprintf("anomaly_%d", time.Now().UnixNano()),
			Type:        "access_request",
			Severity:    ead.getSeverityFromScore(anomalyScore),
			Score:       anomalyScore,
			Description: fmt.Sprintf("Anomalous access request for %s on %s", req.Action, req.Resource),
			DetectedAt:  time.Now(),
			Features:    map[string]float64{"overall_score": anomalyScore},
			Context:     map[string]interface{}{"request": req},
		}
		
		profile.AnomalyHistory = append(profile.AnomalyHistory, anomaly)
	}
	
	profile.LastProfileUpdate = time.Now()
}

func (ead *ExecutiveAnomalyDetector) calculateDistance(lat1, lon1, lat2, lon2 float64) float64 {
	// Haversine formula for calculating distance between two points on Earth
	const R = 6371 // Earth's radius in kilometers
	
	dLat := (lat2 - lat1) * math.Pi / 180
	dLon := (lon2 - lon1) * math.Pi / 180
	
	a := math.Sin(dLat/2)*math.Sin(dLat/2) +
		math.Cos(lat1*math.Pi/180)*math.Cos(lat2*math.Pi/180)*
			math.Sin(dLon/2)*math.Sin(dLon/2)
	
	c := 2 * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))
	
	return R * c
}

func (ead *ExecutiveAnomalyDetector) getSeverityFromScore(score float64) string {
	if score >= 0.9 {
		return "CRITICAL"
	} else if score >= 0.7 {
		return "HIGH"
	} else if score >= 0.5 {
		return "MEDIUM"
	}
	return "LOW"
}