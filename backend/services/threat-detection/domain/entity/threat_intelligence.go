package entity

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// ThreatIntelligence represents threat intelligence information
type ThreatIntelligence struct {
	ID          uuid.UUID    `json:"id" bson:"_id"`
	TenantID    uuid.UUID    `json:"tenant_id" bson:"tenant_id"`
	Name        string       `json:"name" bson:"name"`
	Description string       `json:"description" bson:"description"`
	Type        IntelType    `json:"type" bson:"type"`
	Category    IntelCategory `json:"category" bson:"category"`
	Source      string       `json:"source" bson:"source"`
	
	// Quality and Confidence
	Confidence     IntelConfidence `json:"confidence" bson:"confidence"`
	Reliability    IntelReliability `json:"reliability" bson:"reliability"`
	Quality        IntelQuality    `json:"quality" bson:"quality"`
	Relevance      float64         `json:"relevance" bson:"relevance"`
	
	// Classification
	TLP            TLPLevel        `json:"tlp" bson:"tlp"`
	Classification Classification  `json:"classification" bson:"classification"`
	Sharing        SharingLevel    `json:"sharing" bson:"sharing"`
	
	// Content
	Indicators     []ThreatIndicator `json:"indicators,omitempty" bson:"indicators,omitempty"`
	TTPs           []TTPInfo         `json:"ttps,omitempty" bson:"ttps,omitempty"`
	Vulnerabilities []VulnInfo       `json:"vulnerabilities,omitempty" bson:"vulnerabilities,omitempty"`
	Campaigns      []CampaignInfo    `json:"campaigns,omitempty" bson:"campaigns,omitempty"`
	ThreatActors   []ThreatActorInfo `json:"threat_actors,omitempty" bson:"threat_actors,omitempty"`
	
	// Context and Analysis
	Context        map[string]interface{} `json:"context,omitempty" bson:"context,omitempty"`
	Analysis       *IntelAnalysis         `json:"analysis,omitempty" bson:"analysis,omitempty"`
	Attribution    *AttributionInfo       `json:"attribution,omitempty" bson:"attribution,omitempty"`
	
	// Lifecycle
	FirstSeen      time.Time    `json:"first_seen" bson:"first_seen"`
	LastSeen       time.Time    `json:"last_seen" bson:"last_seen"`
	ValidFrom      time.Time    `json:"valid_from" bson:"valid_from"`
	ValidUntil     *time.Time   `json:"valid_until,omitempty" bson:"valid_until,omitempty"`
	IsActive       bool         `json:"is_active" bson:"is_active"`
	
	// Metadata
	Tags           []string          `json:"tags,omitempty" bson:"tags,omitempty"`
	Labels         map[string]string `json:"labels,omitempty" bson:"labels,omitempty"`
	References     []string          `json:"references,omitempty" bson:"references,omitempty"`
	Hash           string            `json:"hash" bson:"hash"`
	
	// Timestamps
	CreatedAt      time.Time `json:"created_at" bson:"created_at"`
	UpdatedAt      time.Time `json:"updated_at" bson:"updated_at"`
	PublishedAt    time.Time `json:"published_at" bson:"published_at"`
	
	// Versioning
	Version        int `json:"version" bson:"version"`
}

// IntelType represents different types of threat intelligence
type IntelType string

const (
	IntelTypeIndicator     IntelType = "indicator"
	IntelTypeTTP          IntelType = "ttp"
	IntelTypeVulnerability IntelType = "vulnerability"
	IntelTypeCampaign     IntelType = "campaign"
	IntelTypeThreatActor  IntelType = "threat_actor"
	IntelTypeMalware      IntelType = "malware"
	IntelTypeReport       IntelType = "report"
	IntelTypeAlert        IntelType = "alert"
	IntelTypeSighting     IntelType = "sighting"
)

// IntelCategory represents categories of threat intelligence
type IntelCategory string

const (
	IntelCategoryStrategic    IntelCategory = "strategic"
	IntelCategoryTactical     IntelCategory = "tactical"
	IntelCategoryOperational  IntelCategory = "operational"
	IntelCategoryTechnical    IntelCategory = "technical"
)

// IntelConfidence represents confidence levels in threat intelligence
type IntelConfidence string

const (
	IntelConfidenceHigh   IntelConfidence = "high"
	IntelConfidenceMedium IntelConfidence = "medium"
	IntelConfidenceLow    IntelConfidence = "low"
	IntelConfidenceUnknown IntelConfidence = "unknown"
)

// IntelReliability represents reliability of threat intelligence sources
type IntelReliability string

const (
	IntelReliabilityA IntelReliability = "completely_reliable"     // A
	IntelReliabilityB IntelReliability = "usually_reliable"        // B
	IntelReliabilityC IntelReliability = "fairly_reliable"         // C
	IntelReliabilityD IntelReliability = "not_usually_reliable"    // D
	IntelReliabilityE IntelReliability = "unreliable"              // E
	IntelReliabilityF IntelReliability = "reliability_unknown"     // F
)

// IntelQuality represents quality of threat intelligence
type IntelQuality string

const (
	IntelQualityHigh    IntelQuality = "high"
	IntelQualityMedium  IntelQuality = "medium"
	IntelQualityLow     IntelQuality = "low"
	IntelQualityUnknown IntelQuality = "unknown"
)

// TLPLevel represents Traffic Light Protocol levels
type TLPLevel string

const (
	TLPWhite TLPLevel = "white"   // No restrictions
	TLPGreen TLPLevel = "green"   // Community wide
	TLPAmber TLPLevel = "amber"   // Limited distribution
	TLPRed   TLPLevel = "red"     // Internal use only
)

// Classification represents security classification levels
type Classification string

const (
	ClassificationUnclassified Classification = "unclassified"
	ClassificationConfidential Classification = "confidential"
	ClassificationSecret       Classification = "secret"
	ClassificationTopSecret    Classification = "top_secret"
)

// SharingLevel represents sharing permissions
type SharingLevel string

const (
	SharingPublic     SharingLevel = "public"
	SharingCommunity  SharingLevel = "community"
	SharingPartners   SharingLevel = "partners"
	SharingInternal   SharingLevel = "internal"
	SharingRestricted SharingLevel = "restricted"
)

// ThreatIndicator represents a threat indicator with context
type ThreatIndicator struct {
	ID          uuid.UUID       `json:"id" bson:"id"`
	Type        IOCType         `json:"type" bson:"type"`
	Value       string          `json:"value" bson:"value"`
	Pattern     string          `json:"pattern,omitempty" bson:"pattern,omitempty"`
	Description string          `json:"description,omitempty" bson:"description,omitempty"`
	Confidence  float64         `json:"confidence" bson:"confidence"`
	Severity    ThreatSeverity  `json:"severity" bson:"severity"`
	
	// Context
	KillChainPhases []string `json:"kill_chain_phases,omitempty" bson:"kill_chain_phases,omitempty"`
	MITREAttack     *MITREAttackInfo `json:"mitre_attack,omitempty" bson:"mitre_attack,omitempty"`
	
	// Lifecycle
	FirstSeen   time.Time  `json:"first_seen" bson:"first_seen"`
	LastSeen    time.Time  `json:"last_seen" bson:"last_seen"`
	ValidFrom   time.Time  `json:"valid_from" bson:"valid_from"`
	ValidUntil  *time.Time `json:"valid_until,omitempty" bson:"valid_until,omitempty"`
	IsActive    bool       `json:"is_active" bson:"is_active"`
	
	// Detection
	DetectionRule string              `json:"detection_rule,omitempty" bson:"detection_rule,omitempty"`
	Context       map[string]interface{} `json:"context,omitempty" bson:"context,omitempty"`
	Tags          []string            `json:"tags,omitempty" bson:"tags,omitempty"`
}

// TTPInfo represents Tactics, Techniques, and Procedures information
type TTPInfo struct {
	ID            uuid.UUID       `json:"id" bson:"id"`
	Name          string          `json:"name" bson:"name"`
	Description   string          `json:"description" bson:"description"`
	Category      string          `json:"category" bson:"category"`
	MITREAttack   *MITREAttackInfo `json:"mitre_attack,omitempty" bson:"mitre_attack,omitempty"`
	Procedures    []string        `json:"procedures,omitempty" bson:"procedures,omitempty"`
	Tools         []string        `json:"tools,omitempty" bson:"tools,omitempty"`
	Indicators    []uuid.UUID     `json:"indicators,omitempty" bson:"indicators,omitempty"`
	Context       map[string]interface{} `json:"context,omitempty" bson:"context,omitempty"`
	FirstSeen     time.Time       `json:"first_seen" bson:"first_seen"`
	LastSeen      time.Time       `json:"last_seen" bson:"last_seen"`
}

// VulnInfo represents vulnerability information
type VulnInfo struct {
	ID            uuid.UUID       `json:"id" bson:"id"`
	CVE           string          `json:"cve,omitempty" bson:"cve,omitempty"`
	CVSS          float64         `json:"cvss,omitempty" bson:"cvss,omitempty"`
	Severity      ThreatSeverity  `json:"severity" bson:"severity"`
	Title         string          `json:"title" bson:"title"`
	Description   string          `json:"description" bson:"description"`
	Vendor        string          `json:"vendor,omitempty" bson:"vendor,omitempty"`
	Product       string          `json:"product,omitempty" bson:"product,omitempty"`
	Version       string          `json:"version,omitempty" bson:"version,omitempty"`
	PublishedAt   time.Time       `json:"published_at" bson:"published_at"`
	UpdatedAt     time.Time       `json:"updated_at" bson:"updated_at"`
	Exploits      []ExploitInfo   `json:"exploits,omitempty" bson:"exploits,omitempty"`
	References    []string        `json:"references,omitempty" bson:"references,omitempty"`
	Context       map[string]interface{} `json:"context,omitempty" bson:"context,omitempty"`
}

// ExploitInfo represents exploit information
type ExploitInfo struct {
	ID          uuid.UUID `json:"id" bson:"id"`
	Name        string    `json:"name" bson:"name"`
	Type        string    `json:"type" bson:"type"`
	Reliability string    `json:"reliability" bson:"reliability"`
	Source      string    `json:"source" bson:"source"`
	PublishedAt time.Time `json:"published_at" bson:"published_at"`
	References  []string  `json:"references,omitempty" bson:"references,omitempty"`
}

// CampaignInfo represents threat campaign information
type CampaignInfo struct {
	ID            uuid.UUID         `json:"id" bson:"id"`
	Name          string            `json:"name" bson:"name"`
	Aliases       []string          `json:"aliases,omitempty" bson:"aliases,omitempty"`
	Description   string            `json:"description" bson:"description"`
	Objective     string            `json:"objective,omitempty" bson:"objective,omitempty"`
	ThreatActors  []uuid.UUID       `json:"threat_actors,omitempty" bson:"threat_actors,omitempty"`
	TTPs          []uuid.UUID       `json:"ttps,omitempty" bson:"ttps,omitempty"`
	Indicators    []uuid.UUID       `json:"indicators,omitempty" bson:"indicators,omitempty"`
	Targets       []TargetInfo      `json:"targets,omitempty" bson:"targets,omitempty"`
	Timeline      []CampaignEvent   `json:"timeline,omitempty" bson:"timeline,omitempty"`
	FirstSeen     time.Time         `json:"first_seen" bson:"first_seen"`
	LastSeen      time.Time         `json:"last_seen" bson:"last_seen"`
	IsActive      bool              `json:"is_active" bson:"is_active"`
	Context       map[string]interface{} `json:"context,omitempty" bson:"context,omitempty"`
}

// TargetInfo represents campaign target information
type TargetInfo struct {
	Type        string   `json:"type" bson:"type"`
	Industry    string   `json:"industry,omitempty" bson:"industry,omitempty"`
	Geography   string   `json:"geography,omitempty" bson:"geography,omitempty"`
	Size        string   `json:"size,omitempty" bson:"size,omitempty"`
	Description string   `json:"description,omitempty" bson:"description,omitempty"`
	Keywords    []string `json:"keywords,omitempty" bson:"keywords,omitempty"`
}

// CampaignEvent represents an event in a campaign timeline
type CampaignEvent struct {
	Timestamp   time.Time              `json:"timestamp" bson:"timestamp"`
	Type        string                 `json:"type" bson:"type"`
	Description string                 `json:"description" bson:"description"`
	Location    string                 `json:"location,omitempty" bson:"location,omitempty"`
	Targets     []string               `json:"targets,omitempty" bson:"targets,omitempty"`
	Details     map[string]interface{} `json:"details,omitempty" bson:"details,omitempty"`
}

// ThreatActorInfo represents threat actor information
type ThreatActorInfo struct {
	ID            uuid.UUID         `json:"id" bson:"id"`
	Name          string            `json:"name" bson:"name"`
	Aliases       []string          `json:"aliases,omitempty" bson:"aliases,omitempty"`
	Description   string            `json:"description" bson:"description"`
	Type          ActorType         `json:"type" bson:"type"`
	Sophistication ActorSophistication `json:"sophistication" bson:"sophistication"`
	Motivation    []string          `json:"motivation,omitempty" bson:"motivation,omitempty"`
	Goals         []string          `json:"goals,omitempty" bson:"goals,omitempty"`
	Attribution   *AttributionInfo  `json:"attribution,omitempty" bson:"attribution,omitempty"`
	TTPs          []uuid.UUID       `json:"ttps,omitempty" bson:"ttps,omitempty"`
	Campaigns     []uuid.UUID       `json:"campaigns,omitempty" bson:"campaigns,omitempty"`
	Resources     *ActorResources   `json:"resources,omitempty" bson:"resources,omitempty"`
	FirstSeen     time.Time         `json:"first_seen" bson:"first_seen"`
	LastSeen      time.Time         `json:"last_seen" bson:"last_seen"`
	IsActive      bool              `json:"is_active" bson:"is_active"`
	Context       map[string]interface{} `json:"context,omitempty" bson:"context,omitempty"`
}

// ActorType represents different types of threat actors
type ActorType string

const (
	ActorTypeNationState     ActorType = "nation_state"
	ActorTypeCriminal        ActorType = "criminal"
	ActorTypeHacktivist      ActorType = "hacktivist"
	ActorTypeInsider         ActorType = "insider"
	ActorTypeTerrorist       ActorType = "terrorist"
	ActorTypeCompetitor      ActorType = "competitor"
	ActorTypeScriptKiddie    ActorType = "script_kiddie"
	ActorTypeUnknown         ActorType = "unknown"
)

// ActorSophistication represents threat actor sophistication levels
type ActorSophistication string

const (
	ActorSophisticationNone         ActorSophistication = "none"
	ActorSophisticationMinimal      ActorSophistication = "minimal"
	ActorSophisticationIntermediate ActorSophistication = "intermediate"
	ActorSophisticationAdvanced     ActorSophistication = "advanced"
	ActorSophisticationExpert       ActorSophistication = "expert"
	ActorSophisticationInnovator    ActorSophistication = "innovator"
	ActorSophisticationStrategic    ActorSophistication = "strategic"
)

// ActorResources represents threat actor resources and capabilities
type ActorResources struct {
	Funding       string   `json:"funding,omitempty" bson:"funding,omitempty"`
	Personnel     int      `json:"personnel,omitempty" bson:"personnel,omitempty"`
	Infrastructure string  `json:"infrastructure,omitempty" bson:"infrastructure,omitempty"`
	Tools         []string `json:"tools,omitempty" bson:"tools,omitempty"`
	Techniques    []string `json:"techniques,omitempty" bson:"techniques,omitempty"`
	Capabilities  []string `json:"capabilities,omitempty" bson:"capabilities,omitempty"`
}

// AttributionInfo represents attribution information
type AttributionInfo struct {
	Country       string    `json:"country,omitempty" bson:"country,omitempty"`
	Organization  string    `json:"organization,omitempty" bson:"organization,omitempty"`
	Sponsor       string    `json:"sponsor,omitempty" bson:"sponsor,omitempty"`
	Confidence    float64   `json:"confidence" bson:"confidence"`
	Sources       []string  `json:"sources,omitempty" bson:"sources,omitempty"`
	Evidence      []string  `json:"evidence,omitempty" bson:"evidence,omitempty"`
	LastUpdated   time.Time `json:"last_updated" bson:"last_updated"`
}

// IntelAnalysis represents analysis information
type IntelAnalysis struct {
	Summary       string            `json:"summary" bson:"summary"`
	KeyFindings   []string          `json:"key_findings,omitempty" bson:"key_findings,omitempty"`
	Implications  []string          `json:"implications,omitempty" bson:"implications,omitempty"`
	Recommendations []string        `json:"recommendations,omitempty" bson:"recommendations,omitempty"`
	Confidence    float64           `json:"confidence" bson:"confidence"`
	Analyst       string            `json:"analyst,omitempty" bson:"analyst,omitempty"`
	AnalysisDate  time.Time         `json:"analysis_date" bson:"analysis_date"`
	Methodology   string            `json:"methodology,omitempty" bson:"methodology,omitempty"`
	Sources       []string          `json:"sources,omitempty" bson:"sources,omitempty"`
	Limitations   []string          `json:"limitations,omitempty" bson:"limitations,omitempty"`
	NextSteps     []string          `json:"next_steps,omitempty" bson:"next_steps,omitempty"`
}

// Validation methods

// Validate validates the threat intelligence entity
func (ti *ThreatIntelligence) Validate() error {
	if ti.ID == uuid.Nil {
		return fmt.Errorf("threat intelligence ID is required")
	}
	
	if ti.TenantID == uuid.Nil {
		return fmt.Errorf("tenant ID is required")
	}
	
	if ti.Name == "" {
		return fmt.Errorf("threat intelligence name is required")
	}
	
	if ti.Type == "" {
		return fmt.Errorf("threat intelligence type is required")
	}
	
	if ti.Source == "" {
		return fmt.Errorf("source is required")
	}
	
	if ti.ValidFrom.IsZero() {
		return fmt.Errorf("valid from date is required")
	}
	
	if ti.Relevance < 0 || ti.Relevance > 1 {
		return fmt.Errorf("relevance must be between 0 and 1")
	}
	
	return nil
}

// IsValid returns true if the threat intelligence is currently valid
func (ti *ThreatIntelligence) IsValid() bool {
	now := time.Now()
	
	if now.Before(ti.ValidFrom) {
		return false
	}
	
	if ti.ValidUntil != nil && now.After(*ti.ValidUntil) {
		return false
	}
	
	return ti.IsActive
}

// IsExpired returns true if the threat intelligence has expired
func (ti *ThreatIntelligence) IsExpired() bool {
	if ti.ValidUntil == nil {
		return false
	}
	
	return time.Now().After(*ti.ValidUntil)
}

// GetAge returns the age of the threat intelligence
func (ti *ThreatIntelligence) GetAge() time.Duration {
	return time.Since(ti.FirstSeen)
}

// GetConfidenceNumeric returns a numeric representation of confidence
func (ti *ThreatIntelligence) GetConfidenceNumeric() float64 {
	switch ti.Confidence {
	case IntelConfidenceHigh:
		return 1.0
	case IntelConfidenceMedium:
		return 0.7
	case IntelConfidenceLow:
		return 0.4
	case IntelConfidenceUnknown:
		return 0.1
	default:
		return 0.1
	}
}

// GetReliabilityNumeric returns a numeric representation of reliability
func (ti *ThreatIntelligence) GetReliabilityNumeric() float64 {
	switch ti.Reliability {
	case IntelReliabilityA:
		return 1.0
	case IntelReliabilityB:
		return 0.8
	case IntelReliabilityC:
		return 0.6
	case IntelReliabilityD:
		return 0.4
	case IntelReliabilityE:
		return 0.2
	case IntelReliabilityF:
		return 0.1
	default:
		return 0.1
	}
}

// GetQualityNumeric returns a numeric representation of quality
func (ti *ThreatIntelligence) GetQualityNumeric() float64 {
	switch ti.Quality {
	case IntelQualityHigh:
		return 1.0
	case IntelQualityMedium:
		return 0.7
	case IntelQualityLow:
		return 0.4
	case IntelQualityUnknown:
		return 0.1
	default:
		return 0.1
	}
}

// CalculateScore calculates an overall score for the threat intelligence
func (ti *ThreatIntelligence) CalculateScore() float64 {
	confidence := ti.GetConfidenceNumeric()
	reliability := ti.GetReliabilityNumeric()
	quality := ti.GetQualityNumeric()
	relevance := ti.Relevance
	
	// Weighted average: relevance is most important, then reliability, confidence, quality
	score := (relevance * 0.4) + (reliability * 0.3) + (confidence * 0.2) + (quality * 0.1)
	
	return score
}

// UpdateLastSeen updates the last seen timestamp
func (ti *ThreatIntelligence) UpdateLastSeen() {
	ti.LastSeen = time.Now()
	ti.UpdatedAt = time.Now()
	ti.Version++
}

// Deactivate deactivates the threat intelligence
func (ti *ThreatIntelligence) Deactivate() {
	ti.IsActive = false
	ti.UpdatedAt = time.Now()
	ti.Version++
}

// SetExpiration sets the expiration time
func (ti *ThreatIntelligence) SetExpiration(expiration time.Time) {
	ti.ValidUntil = &expiration
	ti.UpdatedAt = time.Now()
	ti.Version++
}

// ToJSON converts the threat intelligence to JSON
func (ti *ThreatIntelligence) ToJSON() ([]byte, error) {
	return json.Marshal(ti)
}

// FromJSON creates threat intelligence from JSON
func (ti *ThreatIntelligence) FromJSON(data []byte) error {
	return json.Unmarshal(data, ti)
}

// Merge merges another threat intelligence with this one
func (ti *ThreatIntelligence) Merge(other *ThreatIntelligence) {
	// Update last seen
	if other.LastSeen.After(ti.LastSeen) {
		ti.LastSeen = other.LastSeen
	}
	
	// Merge indicators
	for _, indicator := range other.Indicators {
		exists := false
		for _, existingIndicator := range ti.Indicators {
			if existingIndicator.Value == indicator.Value && existingIndicator.Type == indicator.Type {
				exists = true
				break
			}
		}
		if !exists {
			ti.Indicators = append(ti.Indicators, indicator)
		}
	}
	
	// Merge TTPs
	for _, ttp := range other.TTPs {
		exists := false
		for _, existingTTP := range ti.TTPs {
			if existingTTP.ID == ttp.ID {
				exists = true
				break
			}
		}
		if !exists {
			ti.TTPs = append(ti.TTPs, ttp)
		}
	}
	
	// Merge tags
	for _, tag := range other.Tags {
		exists := false
		for _, existingTag := range ti.Tags {
			if existingTag == tag {
				exists = true
				break
			}
		}
		if !exists {
			ti.Tags = append(ti.Tags, tag)
		}
	}
	
	// Update metadata
	ti.UpdatedAt = time.Now()
	ti.Version++
}

// MatchesIndicator checks if this threat intelligence matches a given indicator
func (ti *ThreatIntelligence) MatchesIndicator(indicatorType IOCType, value string) bool {
	for _, indicator := range ti.Indicators {
		if indicator.Type == indicatorType && indicator.Value == value {
			return true
		}
	}
	return false
}

// GetActiveIndicators returns only active indicators
func (ti *ThreatIntelligence) GetActiveIndicators() []ThreatIndicator {
	var activeIndicators []ThreatIndicator
	
	for _, indicator := range ti.Indicators {
		if indicator.IsActive {
			activeIndicators = append(activeIndicators, indicator)
		}
	}
	
	return activeIndicators
}

// GetIndicatorsByType returns indicators of a specific type
func (ti *ThreatIntelligence) GetIndicatorsByType(indicatorType IOCType) []ThreatIndicator {
	var indicators []ThreatIndicator
	
	for _, indicator := range ti.Indicators {
		if indicator.Type == indicatorType {
			indicators = append(indicators, indicator)
		}
	}
	
	return indicators
}