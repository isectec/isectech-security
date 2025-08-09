package usecase

import (
	"context"
	"fmt"
	"time"

	"github.com/isectech/platform/services/event-processor/domain/entity"
	"github.com/isectech/platform/services/event-processor/domain/repository"
	"github.com/isectech/platform/services/event-processor/domain/service"
	"github.com/isectech/platform/shared/common"
	"github.com/isectech/platform/shared/types"
	"github.com/isectech/platform/pkg/logging"
	"github.com/isectech/platform/pkg/metrics"
)

// ProcessEventUseCase represents the use case for processing events
type ProcessEventUseCase struct {
	eventRepo           repository.EventRepository
	processorService    service.EventProcessorService
	enrichmentService   service.EventEnrichmentService
	validationService   service.EventValidationService
	normalizationService service.EventNormalizationService
	riskAssessmentService service.RiskAssessmentService
	logger              *logging.Logger
	metrics             *metrics.Collector
}

// NewProcessEventUseCase creates a new ProcessEventUseCase
func NewProcessEventUseCase(
	eventRepo repository.EventRepository,
	processorService service.EventProcessorService,
	enrichmentService service.EventEnrichmentService,
	validationService service.EventValidationService,
	normalizationService service.EventNormalizationService,
	riskAssessmentService service.RiskAssessmentService,
	logger *logging.Logger,
	metrics *metrics.Collector,
) *ProcessEventUseCase {
	return &ProcessEventUseCase{
		eventRepo:            eventRepo,
		processorService:     processorService,
		enrichmentService:    enrichmentService,
		validationService:    validationService,
		normalizationService: normalizationService,
		riskAssessmentService: riskAssessmentService,
		logger:               logger,
		metrics:              metrics,
	}
}

// ProcessEventRequest represents a request to process an event
type ProcessEventRequest struct {
	Event            *entity.Event `json:"event"`
	RequestContext   *types.RequestContext `json:"request_context"`
	ProcessingConfig *ProcessingConfig `json:"processing_config,omitempty"`
}

// ProcessingConfig represents configuration for event processing
type ProcessingConfig struct {
	EnableValidation    bool          `json:"enable_validation"`
	EnableNormalization bool          `json:"enable_normalization"`
	EnableEnrichment    bool          `json:"enable_enrichment"`
	EnableRiskAssessment bool         `json:"enable_risk_assessment"`
	EnableCorrelation   bool          `json:"enable_correlation"`
	Timeout            time.Duration `json:"timeout"`
	RetryAttempts      int           `json:"retry_attempts"`
}

// ProcessEventResponse represents the response from processing an event
type ProcessEventResponse struct {
	EventID       types.EventID        `json:"event_id"`
	Status        entity.EventStatus   `json:"status"`
	ProcessedAt   time.Time            `json:"processed_at"`
	Duration      time.Duration        `json:"duration"`
	RiskScore     float64              `json:"risk_score,omitempty"`
	RiskFactors   []string             `json:"risk_factors,omitempty"`
	Warnings      []ProcessingWarning  `json:"warnings,omitempty"`
	Correlations  []types.EventID      `json:"correlations,omitempty"`
	ProcessingLog []entity.ProcessingEntry `json:"processing_log"`
}

// ProcessingWarning represents a warning during event processing
type ProcessingWarning struct {
	Code        string `json:"code"`
	Message     string `json:"message"`
	Step        string `json:"step"`
	Severity    string `json:"severity"`
	Recoverable bool   `json:"recoverable"`
}

// Execute processes a single event
func (uc *ProcessEventUseCase) Execute(ctx context.Context, req *ProcessEventRequest) (*ProcessEventResponse, error) {
	// Start timing
	start := time.Now()
	
	// Create logger with context
	logger := uc.logger.WithRequestContext(req.RequestContext)
	
	// Validate request
	if req.Event == nil {
		logger.Error("Event is required")
		return nil, common.ErrInvalidInput("event")
	}
	
	// Set default processing config
	config := req.ProcessingConfig
	if config == nil {
		config = &ProcessingConfig{
			EnableValidation:     true,
			EnableNormalization:  true,
			EnableEnrichment:     true,
			EnableRiskAssessment: true,
			EnableCorrelation:    true,
			Timeout:             30 * time.Second,
			RetryAttempts:       3,
		}
	}
	
	// Create context with timeout
	processCtx, cancel := context.WithTimeout(ctx, config.Timeout)
	defer cancel()
	
	event := req.Event
	var warnings []ProcessingWarning
	var correlatedEvents []types.EventID
	
	logger.Info("Starting event processing",
		logging.String("event_id", event.ID.String()),
		logging.String("event_type", string(event.Type)),
		logging.String("source", event.Source),
	)
	
	// Record metrics
	uc.metrics.RecordBusinessOperation("event_processing", event.TenantID.String(), "started", 0)
	
	// Step 1: Validate event
	if config.EnableValidation {
		if err := uc.validateEvent(processCtx, event, logger); err != nil {
			return uc.handleProcessingError(event, "validation", err, start, logger)
		}
	}
	
	// Step 2: Normalize event
	if config.EnableNormalization {
		if err := uc.normalizeEvent(processCtx, event, logger); err != nil {
			// Normalization errors are usually non-fatal
			warning := ProcessingWarning{
				Code:        "NORMALIZATION_ERROR",
				Message:     err.Error(),
				Step:        "normalization",
				Severity:    "warning",
				Recoverable: true,
			}
			warnings = append(warnings, warning)
			logger.Warn("Event normalization failed", logging.String("error", err.Error()))
		}
	}
	
	// Step 3: Store initial event
	event.AddProcessingStep("persistence", "event-repository")
	if err := uc.eventRepo.Create(processCtx, event); err != nil {
		return uc.handleProcessingError(event, "persistence", err, start, logger)
	}
	event.CompleteProcessingStep(map[string]interface{}{"stored": true}, nil)
	
	// Step 4: Enrich event
	if config.EnableEnrichment {
		if err := uc.enrichEvent(processCtx, event, logger); err != nil {
			// Enrichment errors are usually non-fatal
			warning := ProcessingWarning{
				Code:        "ENRICHMENT_ERROR",
				Message:     err.Error(),
				Step:        "enrichment",
				Severity:    "warning",
				Recoverable: true,
			}
			warnings = append(warnings, warning)
			logger.Warn("Event enrichment failed", logging.String("error", err.Error()))
		}
	}
	
	// Step 5: Risk assessment
	var riskScore float64
	var riskFactors []string
	if config.EnableRiskAssessment {
		if assessment, err := uc.assessRisk(processCtx, event, logger); err != nil {
			warning := ProcessingWarning{
				Code:        "RISK_ASSESSMENT_ERROR",
				Message:     err.Error(),
				Step:        "risk_assessment",
				Severity:    "warning",
				Recoverable: true,
			}
			warnings = append(warnings, warning)
			logger.Warn("Risk assessment failed", logging.String("error", err.Error()))
		} else if assessment != nil {
			riskScore = assessment.Score
			for _, factor := range assessment.Factors {
				riskFactors = append(riskFactors, factor.Name)
			}
			event.SetRiskScore(assessment.Score, assessment.Confidence)
			for _, factor := range riskFactors {
				event.AddRiskFactor(factor)
			}
		}
	}
	
	// Step 6: Event correlation
	if config.EnableCorrelation {
		if related, err := uc.correlateEvent(processCtx, event, logger); err != nil {
			warning := ProcessingWarning{
				Code:        "CORRELATION_ERROR",
				Message:     err.Error(),
				Step:        "correlation",
				Severity:    "warning",
				Recoverable: true,
			}
			warnings = append(warnings, warning)
			logger.Warn("Event correlation failed", logging.String("error", err.Error()))
		} else {
			for _, relatedEvent := range related {
				correlatedEvents = append(correlatedEvents, relatedEvent.ID)
			}
		}
	}
	
	// Step 7: Final update
	event.SetStatus(entity.EventStatusProcessed)
	if err := uc.eventRepo.Update(processCtx, event); err != nil {
		return uc.handleProcessingError(event, "final_update", err, start, logger)
	}
	
	// Calculate duration
	duration := time.Since(start)
	
	// Record metrics
	uc.metrics.RecordBusinessOperation("event_processing", event.TenantID.String(), "completed", duration)
	uc.metrics.RecordSecurityEvent(string(event.Type), string(event.Severity), event.TenantID.String())
	
	logger.Info("Event processing completed",
		logging.String("event_id", event.ID.String()),
		logging.Duration("duration", duration),
		logging.Float64("risk_score", riskScore),
		logging.Int("correlations", len(correlatedEvents)),
		logging.Int("warnings", len(warnings)),
	)
	
	return &ProcessEventResponse{
		EventID:       event.ID,
		Status:        event.Status,
		ProcessedAt:   time.Now().UTC(),
		Duration:      duration,
		RiskScore:     riskScore,
		RiskFactors:   riskFactors,
		Warnings:      warnings,
		Correlations:  correlatedEvents,
		ProcessingLog: event.ProcessingLog,
	}, nil
}

// validateEvent validates the event
func (uc *ProcessEventUseCase) validateEvent(ctx context.Context, event *entity.Event, logger *logging.Logger) error {
	event.AddProcessingStep("validation", "event-validator")
	
	// Basic entity validation
	if err := event.Validate(); err != nil {
		event.CompleteProcessingStep(nil, err)
		return fmt.Errorf("basic validation failed: %w", err)
	}
	
	// Schema validation
	if err := uc.validationService.ValidateSchema(ctx, event); err != nil {
		event.CompleteProcessingStep(nil, err)
		return fmt.Errorf("schema validation failed: %w", err)
	}
	
	// Business rules validation
	if err := uc.validationService.ValidateBusinessRules(ctx, event); err != nil {
		event.CompleteProcessingStep(nil, err)
		return fmt.Errorf("business rules validation failed: %w", err)
	}
	
	// Data integrity validation
	if err := uc.validationService.ValidateDataIntegrity(ctx, event); err != nil {
		event.CompleteProcessingStep(nil, err)
		return fmt.Errorf("data integrity validation failed: %w", err)
	}
	
	// Compliance validation
	if err := uc.validationService.ValidateCompliance(ctx, event); err != nil {
		event.CompleteProcessingStep(nil, err)
		return fmt.Errorf("compliance validation failed: %w", err)
	}
	
	event.CompleteProcessingStep(map[string]interface{}{"validated": true}, nil)
	logger.Debug("Event validation completed", logging.String("event_id", event.ID.String()))
	
	return nil
}

// normalizeEvent normalizes the event
func (uc *ProcessEventUseCase) normalizeEvent(ctx context.Context, event *entity.Event, logger *logging.Logger) error {
	event.AddProcessingStep("normalization", "event-normalizer")
	
	// Normalize timestamps
	if err := uc.normalizationService.NormalizeTimestamps(ctx, event); err != nil {
		event.CompleteProcessingStep(nil, err)
		return fmt.Errorf("timestamp normalization failed: %w", err)
	}
	
	// Normalize IP addresses
	if err := uc.normalizationService.NormalizeIPAddresses(ctx, event); err != nil {
		event.CompleteProcessingStep(nil, err)
		return fmt.Errorf("IP address normalization failed: %w", err)
	}
	
	// Normalize field names
	if err := uc.normalizationService.NormalizeFieldNames(ctx, event); err != nil {
		event.CompleteProcessingStep(nil, err)
		return fmt.Errorf("field name normalization failed: %w", err)
	}
	
	// Normalize values
	if err := uc.normalizationService.NormalizeValues(ctx, event); err != nil {
		event.CompleteProcessingStep(nil, err)
		return fmt.Errorf("value normalization failed: %w", err)
	}
	
	// Apply field mappings
	if err := uc.normalizationService.ApplyFieldMappings(ctx, event); err != nil {
		event.CompleteProcessingStep(nil, err)
		return fmt.Errorf("field mapping failed: %w", err)
	}
	
	event.CompleteProcessingStep(map[string]interface{}{"normalized": true}, nil)
	logger.Debug("Event normalization completed", logging.String("event_id", event.ID.String()))
	
	return nil
}

// enrichEvent enriches the event with additional information
func (uc *ProcessEventUseCase) enrichEvent(ctx context.Context, event *entity.Event, logger *logging.Logger) error {
	event.AddProcessingStep("enrichment", "event-enricher")
	
	var enrichmentResults []string
	
	// Enrich with asset information
	if err := uc.enrichmentService.EnrichWithAssetInfo(ctx, event); err != nil {
		logger.Warn("Asset enrichment failed", logging.String("error", err.Error()))
	} else {
		enrichmentResults = append(enrichmentResults, "asset_info")
	}
	
	// Enrich with user information
	if err := uc.enrichmentService.EnrichWithUserInfo(ctx, event); err != nil {
		logger.Warn("User enrichment failed", logging.String("error", err.Error()))
	} else {
		enrichmentResults = append(enrichmentResults, "user_info")
	}
	
	// Enrich with geo location
	if err := uc.enrichmentService.EnrichWithGeoLocation(ctx, event); err != nil {
		logger.Warn("Geo location enrichment failed", logging.String("error", err.Error()))
	} else {
		enrichmentResults = append(enrichmentResults, "geo_location")
	}
	
	// Enrich with threat intelligence
	if err := uc.enrichmentService.EnrichWithThreatIntelligence(ctx, event); err != nil {
		logger.Warn("Threat intelligence enrichment failed", logging.String("error", err.Error()))
	} else {
		enrichmentResults = append(enrichmentResults, "threat_intelligence")
	}
	
	// Enrich with network information
	if err := uc.enrichmentService.EnrichWithNetworkInfo(ctx, event); err != nil {
		logger.Warn("Network enrichment failed", logging.String("error", err.Error()))
	} else {
		enrichmentResults = append(enrichmentResults, "network_info")
	}
	
	event.CompleteProcessingStep(map[string]interface{}{
		"enriched":          true,
		"enrichment_types": enrichmentResults,
	}, nil)
	
	logger.Debug("Event enrichment completed",
		logging.String("event_id", event.ID.String()),
		logging.Any("enrichment_types", enrichmentResults),
	)
	
	return nil
}

// assessRisk performs risk assessment on the event
func (uc *ProcessEventUseCase) assessRisk(ctx context.Context, event *entity.Event, logger *logging.Logger) (*service.RiskAssessment, error) {
	event.AddProcessingStep("risk_assessment", "risk-assessor")
	
	assessment, err := uc.riskAssessmentService.CalculateRiskScore(ctx, event)
	if err != nil {
		event.CompleteProcessingStep(nil, err)
		return nil, fmt.Errorf("risk assessment failed: %w", err)
	}
	
	event.CompleteProcessingStep(map[string]interface{}{
		"risk_score":  assessment.Score,
		"confidence":  assessment.Confidence,
		"factor_count": len(assessment.Factors),
	}, nil)
	
	logger.Debug("Risk assessment completed",
		logging.String("event_id", event.ID.String()),
		logging.Float64("risk_score", assessment.Score),
		logging.Float64("confidence", assessment.Confidence),
	)
	
	return assessment, nil
}

// correlateEvent performs event correlation
func (uc *ProcessEventUseCase) correlateEvent(ctx context.Context, event *entity.Event, logger *logging.Logger) ([]*entity.Event, error) {
	event.AddProcessingStep("correlation", "event-correlator")
	
	relatedEvents, err := uc.processorService.CorrelatEvents(ctx, event)
	if err != nil {
		event.CompleteProcessingStep(nil, err)
		return nil, fmt.Errorf("event correlation failed: %w", err)
	}
	
	event.CompleteProcessingStep(map[string]interface{}{
		"correlated":      true,
		"related_events": len(relatedEvents),
	}, nil)
	
	logger.Debug("Event correlation completed",
		logging.String("event_id", event.ID.String()),
		logging.Int("related_events", len(relatedEvents)),
	)
	
	return relatedEvents, nil
}

// handleProcessingError handles processing errors
func (uc *ProcessEventUseCase) handleProcessingError(
	event *entity.Event,
	step string,
	err error,
	startTime time.Time,
	logger *logging.Logger,
) (*ProcessEventResponse, error) {
	duration := time.Since(startTime)
	
	// Set event status to failed
	event.SetStatus(entity.EventStatusFailed)
	
	// Update event in repository if possible
	if updateErr := uc.eventRepo.Update(context.Background(), event); updateErr != nil {
		logger.Error("Failed to update event status to failed",
			logging.String("event_id", event.ID.String()),
			logging.String("error", updateErr.Error()),
		)
	}
	
	// Record metrics
	uc.metrics.RecordBusinessOperation("event_processing", event.TenantID.String(), "failed", duration)
	uc.metrics.RecordError("processing_error", "event-processor")
	
	logger.Error("Event processing failed",
		logging.String("event_id", event.ID.String()),
		logging.String("step", step),
		logging.String("error", err.Error()),
		logging.Duration("duration", duration),
	)
	
	return &ProcessEventResponse{
		EventID:       event.ID,
		Status:        entity.EventStatusFailed,
		ProcessedAt:   time.Now().UTC(),
		Duration:      duration,
		ProcessingLog: event.ProcessingLog,
	}, common.WrapError(err, common.ErrCodeInternal, fmt.Sprintf("event processing failed at step: %s", step))
}

// ProcessEventBatchRequest represents a request to process multiple events
type ProcessEventBatchRequest struct {
	Events           []*entity.Event   `json:"events"`
	RequestContext   *types.RequestContext `json:"request_context"`
	ProcessingConfig *ProcessingConfig `json:"processing_config,omitempty"`
	BatchSize        int               `json:"batch_size,omitempty"`
	Parallel         bool              `json:"parallel,omitempty"`
}

// ProcessEventBatchResponse represents the response from processing multiple events
type ProcessEventBatchResponse struct {
	TotalEvents      int                       `json:"total_events"`
	SuccessfulEvents int                       `json:"successful_events"`
	FailedEvents     int                       `json:"failed_events"`
	Duration         time.Duration             `json:"duration"`
	Results          []*ProcessEventResponse   `json:"results"`
	Errors           []BatchProcessingError    `json:"errors,omitempty"`
}

// BatchProcessingError represents an error in batch processing
type BatchProcessingError struct {
	EventID types.EventID `json:"event_id"`
	Error   string        `json:"error"`
	Step    string        `json:"step"`
}

// ExecuteBatch processes multiple events in batch
func (uc *ProcessEventUseCase) ExecuteBatch(ctx context.Context, req *ProcessEventBatchRequest) (*ProcessEventBatchResponse, error) {
	start := time.Now()
	
	logger := uc.logger.WithRequestContext(req.RequestContext)
	
	if len(req.Events) == 0 {
		return nil, common.ErrInvalidInput("events cannot be empty")
	}
	
	batchSize := req.BatchSize
	if batchSize <= 0 {
		batchSize = 100 // Default batch size
	}
	
	logger.Info("Starting batch event processing",
		logging.Int("total_events", len(req.Events)),
		logging.Int("batch_size", batchSize),
		logging.Bool("parallel", req.Parallel),
	)
	
	var results []*ProcessEventResponse
	var errors []BatchProcessingError
	
	// Process events in batches
	for i := 0; i < len(req.Events); i += batchSize {
		end := i + batchSize
		if end > len(req.Events) {
			end = len(req.Events)
		}
		
		batch := req.Events[i:end]
		batchResults, batchErrors := uc.processBatch(ctx, batch, req.RequestContext, req.ProcessingConfig, req.Parallel, logger)
		
		results = append(results, batchResults...)
		errors = append(errors, batchErrors...)
	}
	
	duration := time.Since(start)
	successfulEvents := 0
	failedEvents := 0
	
	for _, result := range results {
		if result.Status == entity.EventStatusProcessed {
			successfulEvents++
		} else {
			failedEvents++
		}
	}
	
	logger.Info("Batch event processing completed",
		logging.Int("total_events", len(req.Events)),
		logging.Int("successful_events", successfulEvents),
		logging.Int("failed_events", failedEvents),
		logging.Duration("duration", duration),
	)
	
	return &ProcessEventBatchResponse{
		TotalEvents:      len(req.Events),
		SuccessfulEvents: successfulEvents,
		FailedEvents:     failedEvents,
		Duration:         duration,
		Results:          results,
		Errors:           errors,
	}, nil
}

// processBatch processes a single batch of events
func (uc *ProcessEventUseCase) processBatch(
	ctx context.Context,
	events []*entity.Event,
	requestContext *types.RequestContext,
	config *ProcessingConfig,
	parallel bool,
	logger *logging.Logger,
) ([]*ProcessEventResponse, []BatchProcessingError) {
	var results []*ProcessEventResponse
	var errors []BatchProcessingError
	
	if parallel {
		// Process events in parallel
		resultChan := make(chan *ProcessEventResponse, len(events))
		errorChan := make(chan BatchProcessingError, len(events))
		
		for _, event := range events {
			go func(e *entity.Event) {
				req := &ProcessEventRequest{
					Event:            e,
					RequestContext:   requestContext,
					ProcessingConfig: config,
				}
				
				result, err := uc.Execute(ctx, req)
				if err != nil {
					errorChan <- BatchProcessingError{
						EventID: e.ID,
						Error:   err.Error(),
						Step:    "processing",
					}
					return
				}
				
				resultChan <- result
			}(event)
		}
		
		// Collect results
		for i := 0; i < len(events); i++ {
			select {
			case result := <-resultChan:
				results = append(results, result)
			case error := <-errorChan:
				errors = append(errors, error)
			case <-ctx.Done():
				logger.Error("Batch processing timeout", logging.String("error", ctx.Err().Error()))
				return results, errors
			}
		}
	} else {
		// Process events sequentially
		for _, event := range events {
			req := &ProcessEventRequest{
				Event:            event,
				RequestContext:   requestContext,
				ProcessingConfig: config,
			}
			
			result, err := uc.Execute(ctx, req)
			if err != nil {
				errors = append(errors, BatchProcessingError{
					EventID: event.ID,
					Error:   err.Error(),
					Step:    "processing",
				})
				continue
			}
			
			results = append(results, result)
		}
	}
	
	return results, errors
}