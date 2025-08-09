package stream_processing

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
)

// NewWorkerPool creates a new worker pool
func NewWorkerPool(
	logger *zap.Logger,
	workerCount int,
	bufferSize int,
	streamProcessorManager *StreamProcessorManager,
	ctx context.Context,
) (*WorkerPool, error) {
	ctx, cancel := context.WithCancel(ctx)
	
	pool := &WorkerPool{
		logger:      logger.With(zap.String("component", "worker-pool")),
		workerCount: workerCount,
		workChan:    make(chan *StreamProcessingTask, bufferSize),
		workers:     make([]*StreamWorker, workerCount),
		ctx:         ctx,
		cancel:      cancel,
	}
	
	// Create workers
	for i := 0; i < workerCount; i++ {
		worker := &StreamWorker{
			id:                     i,
			logger:                 logger.With(zap.Int("worker_id", i)),
			workChan:               pool.workChan,
			streamProcessorManager: streamProcessorManager,
			ctx:                    ctx,
		}
		pool.workers[i] = worker
	}
	
	logger.Info("Worker pool created",
		zap.Int("worker_count", workerCount),
		zap.Int("buffer_size", bufferSize),
	)
	
	return pool, nil
}

// Start starts all workers in the pool
func (p *WorkerPool) Start() error {
	p.logger.Info("Starting worker pool...")
	
	// Start all workers
	for _, worker := range p.workers {
		p.wg.Add(1)
		go worker.run(&p.wg)
	}
	
	p.logger.Info("Worker pool started", zap.Int("worker_count", len(p.workers)))
	return nil
}

// Stop stops all workers in the pool
func (p *WorkerPool) Stop() {
	p.logger.Info("Stopping worker pool...")
	
	// Cancel context to signal workers to stop
	p.cancel()
	
	// Close work channel
	close(p.workChan)
	
	// Wait for all workers to finish
	p.wg.Wait()
	
	p.logger.Info("Worker pool stopped")
}

// IsHealthy returns the health status of the worker pool
func (p *WorkerPool) IsHealthy() bool {
	// Check if work channel is not blocked
	select {
	case p.workChan <- nil:
		// Channel is not full, remove the nil task
		<-p.workChan
		return true
	default:
		// Channel is full
		return false
	}
}

// run runs a stream worker
func (w *StreamWorker) run(wg *sync.WaitGroup) {
	defer wg.Done()
	
	w.logger.Info("Stream worker started")
	
	for {
		select {
		case <-w.ctx.Done():
			w.logger.Info("Stream worker stopping due to context cancellation")
			return
		case task, ok := <-w.workChan:
			if !ok {
				w.logger.Info("Work channel closed, worker stopping")
				return
			}
			
			// Skip nil tasks (used for health checks)
			if task == nil {
				continue
			}
			
			w.processTask(task)
		}
	}
}

// processTask processes a single stream processing task
func (w *StreamWorker) processTask(task *StreamProcessingTask) {
	start := time.Now()
	
	w.logger.Debug("Processing task",
		zap.String("topic", task.Topic),
		zap.Int("partition", task.Partition),
		zap.Int64("offset", task.Offset),
	)
	
	// Parse the message
	var event map[string]interface{}
	if err := json.Unmarshal(task.Message.Value, &event); err != nil {
		w.logger.Error("Failed to unmarshal event",
			zap.Error(err),
			zap.String("topic", task.Topic),
			zap.Int64("offset", task.Offset),
		)
		return
	}
	
	// Add message metadata to event
	event["_kafka_topic"] = task.Topic
	event["_kafka_partition"] = task.Partition
	event["_kafka_offset"] = task.Offset
	event["_kafka_timestamp"] = task.Message.Time
	
	// Extract headers
	headers := make(map[string]string)
	for _, header := range task.Message.Headers {
		headers[header.Key] = string(header.Value)
	}
	if len(headers) > 0 {
		event["_kafka_headers"] = headers
	}
	
	// Process the event through the stream processing pipeline
	ctx, cancel := context.WithTimeout(w.ctx, 30*time.Second)
	defer cancel()
	
	result, err := w.streamProcessorManager.ProcessEvent(ctx, event)
	if err != nil {
		w.logger.Error("Failed to process event",
			zap.Error(err),
			zap.String("topic", task.Topic),
			zap.Int64("offset", task.Offset),
		)
		
		// TODO: Send to dead letter queue or retry
		return
	}
	
	// Publish results to appropriate output topics
	w.publishResults(result, task)
	
	duration := time.Since(start)
	w.logger.Debug("Task processed successfully",
		zap.String("topic", task.Topic),
		zap.Int64("offset", task.Offset),
		zap.Duration("duration", duration),
		zap.Bool("success", result.Success),
		zap.Int("alerts_generated", len(result.Alerts)),
	)
}

// publishResults publishes processing results to output topics
func (w *StreamWorker) publishResults(result *ProcessingResult, originalTask *StreamProcessingTask) {
	// Get Kafka writers from the processor (this would need to be passed to the worker)
	// For now, we'll log the results
	
	w.logger.Info("Publishing processing results",
		zap.Bool("success", result.Success),
		zap.Int("alerts", len(result.Alerts)),
		zap.Int("patterns_matched", len(result.MatchedPatterns)),
		zap.Float64("anomaly_score", result.AnomalyScore),
		zap.Duration("processing_time", result.ProcessingTime),
	)
	
	// In a real implementation, we would:
	// 1. Publish enriched events to enriched-events topic
	// 2. Publish alerts to alerts topic
	// 3. Publish correlation results to correlation topic
	// 4. Publish errors to error topic
	
	// Example of what the publishing would look like:
	/*
	// Publish enriched event
	enrichedEventData, _ := json.Marshal(result.ProcessedEvent)
	enrichedMessage := kafka.Message{
		Key:   originalTask.Message.Key,
		Value: enrichedEventData,
		Headers: []kafka.Header{
			{Key: "processing_time", Value: []byte(result.ProcessingTime.String())},
			{Key: "original_topic", Value: []byte(originalTask.Topic)},
		},
	}
	
	if enrichedWriter, exists := writers["enriched"]; exists {
		enrichedWriter.WriteMessages(context.Background(), enrichedMessage)
	}
	
	// Publish alerts
	for _, alert := range result.Alerts {
		alertData, _ := json.Marshal(alert)
		alertMessage := kafka.Message{
			Key:   []byte(alert.ID),
			Value: alertData,
			Headers: []kafka.Header{
				{Key: "severity", Value: []byte(alert.Severity)},
				{Key: "alert_type", Value: []byte(alert.Type)},
			},
		}
		
		if alertWriter, exists := writers["alerts"]; exists {
			alertWriter.WriteMessages(context.Background(), alertMessage)
		}
	}
	*/
}

// StreamProcessingMetrics handles metrics collection for stream processing
type StreamProcessingMetrics struct {
	logger           *zap.Logger
	processedEvents  int64
	failedEvents     int64
	alertsGenerated  int64
	totalProcessingTime time.Duration
	mu               sync.RWMutex
}

// NewStreamProcessingMetrics creates a new metrics collector
func NewStreamProcessingMetrics(logger *zap.Logger) *StreamProcessingMetrics {
	return &StreamProcessingMetrics{
		logger: logger.With(zap.String("component", "stream-processing-metrics")),
	}
}

// RecordEventProcessed records a processed event
func (m *StreamProcessingMetrics) RecordEventProcessed(processingTime time.Duration, success bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	if success {
		m.processedEvents++
	} else {
		m.failedEvents++
	}
	
	m.totalProcessingTime += processingTime
}

// RecordAlertGenerated records generated alerts
func (m *StreamProcessingMetrics) RecordAlertGenerated(count int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	m.alertsGenerated += int64(count)
}

// GetCurrentMetrics returns current metrics
func (m *StreamProcessingMetrics) GetCurrentMetrics() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	totalEvents := m.processedEvents + m.failedEvents
	var avgProcessingTime time.Duration
	if totalEvents > 0 {
		avgProcessingTime = m.totalProcessingTime / time.Duration(totalEvents)
	}
	
	return map[string]interface{}{
		"processed_events":     m.processedEvents,
		"failed_events":        m.failedEvents,
		"alerts_generated":     m.alertsGenerated,
		"total_events":         totalEvents,
		"avg_processing_time":  avgProcessingTime,
		"total_processing_time": m.totalProcessingTime,
	}
}

// ReportMetrics reports current metrics
func (m *StreamProcessingMetrics) ReportMetrics() {
	metrics := m.GetCurrentMetrics()
	
	m.logger.Info("Stream processing metrics",
		zap.Any("metrics", metrics),
	)
}

// HealthChecker monitors the health of stream processing components
type HealthChecker struct {
	logger     *zap.Logger
	interval   time.Duration
	components map[string]bool
	mu         sync.RWMutex
}

// NewHealthChecker creates a new health checker
func NewHealthChecker(logger *zap.Logger, interval time.Duration) *HealthChecker {
	return &HealthChecker{
		logger:     logger.With(zap.String("component", "health-checker")),
		interval:   interval,
		components: make(map[string]bool),
	}
}

// CheckComponent checks the health of a component
func (h *HealthChecker) CheckComponent(name string, healthy bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	
	h.components[name] = healthy
	
	h.logger.Debug("Component health check",
		zap.String("component", name),
		zap.Bool("healthy", healthy),
	)
}

// GetOverallHealth returns the overall health status
func (h *HealthChecker) GetOverallHealth() string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	
	allHealthy := true
	for _, healthy := range h.components {
		if !healthy {
			allHealthy = false
			break
		}
	}
	
	if allHealthy {
		return "healthy"
	}
	return "unhealthy"
}

// GetComponentHealth returns the health status of all components
func (h *HealthChecker) GetComponentHealth() map[string]bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	
	// Return a copy
	result := make(map[string]bool)
	for name, healthy := range h.components {
		result[name] = healthy
	}
	
	return result
}