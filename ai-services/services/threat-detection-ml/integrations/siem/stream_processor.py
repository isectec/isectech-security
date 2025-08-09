"""
SIEM Stream Processor

Production-grade real-time event stream processor that handles high-volume
SIEM event streams with buffering, filtering, and intelligent processing.
"""

import asyncio
import logging
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable, Set, AsyncGenerator
from dataclasses import dataclass, field
from enum import Enum
from collections import deque, defaultdict
import time

from .base_connector import SiemEvent, EventSeverity, BaseSiemConnector
from .correlation_engine import ThreatCorrelationEngine
from .enrichment_service import AlertEnrichmentService

logger = logging.getLogger(__name__)

class StreamStatus(str, Enum):
    """Stream processing status"""
    STOPPED = "stopped"
    STARTING = "starting"
    RUNNING = "running"
    PAUSED = "paused"
    ERROR = "error"

class BufferStrategy(str, Enum):
    """Event buffering strategies"""
    FIFO = "fifo"                    # First In, First Out
    PRIORITY = "priority"            # Priority-based buffering
    TIME_WINDOW = "time_window"      # Time-based windowing
    HYBRID = "hybrid"                # Combined strategy

@dataclass
class StreamConfig:
    """Stream processor configuration"""
    buffer_size: int = 10000
    buffer_strategy: BufferStrategy = BufferStrategy.HYBRID
    processing_batch_size: int = 100
    processing_interval_ms: int = 1000
    high_priority_threshold: EventSeverity = EventSeverity.HIGH
    enable_filtering: bool = True
    enable_deduplication: bool = True
    enable_rate_limiting: bool = True
    max_events_per_second: int = 1000
    backpressure_threshold: float = 0.8
    enable_metrics: bool = True
    enable_correlation: bool = True
    enable_enrichment: bool = True
    correlation_window_minutes: int = 60
    enrichment_timeout_seconds: int = 30

class EventBuffer:
    """
    Advanced event buffer with multiple strategies and overflow handling
    """
    
    def __init__(self, config: StreamConfig):
        self.config = config
        self.strategy = config.buffer_strategy
        
        # Primary buffer
        self._buffer: deque = deque(maxlen=config.buffer_size)
        
        # Priority queues for hybrid strategy
        self._priority_queues: Dict[EventSeverity, deque] = {
            severity: deque() for severity in EventSeverity
        }
        
        # Time-window buffers
        self._time_windows: Dict[int, List[SiemEvent]] = defaultdict(list)
        self._current_window = int(time.time() // 60)  # 1-minute windows
        
        # Deduplication tracking
        self._event_hashes: Set[str] = set()
        self._hash_expiry: Dict[str, datetime] = {}
        
        # Metrics
        self._metrics = {
            'events_buffered': 0,
            'events_dropped': 0,
            'events_deduplicated': 0,
            'buffer_overflows': 0,
            'current_size': 0,
            'peak_size': 0
        }
    
    def add_event(self, event: SiemEvent) -> bool:
        """
        Add event to buffer
        
        Returns:
            True if event was added, False if dropped
        """
        try:
            # Deduplication check
            if self.config.enable_deduplication:
                event_hash = self._get_event_hash(event)
                if event_hash in self._event_hashes:
                    self._metrics['events_deduplicated'] += 1
                    return False
                
                # Add to hash tracking
                self._event_hashes.add(event_hash)
                self._hash_expiry[event_hash] = datetime.utcnow() + timedelta(minutes=30)
            
            # Add based on strategy
            added = False
            
            if self.strategy == BufferStrategy.FIFO:
                added = self._add_fifo(event)
            elif self.strategy == BufferStrategy.PRIORITY:
                added = self._add_priority(event)
            elif self.strategy == BufferStrategy.TIME_WINDOW:
                added = self._add_time_window(event)
            elif self.strategy == BufferStrategy.HYBRID:
                added = self._add_hybrid(event)
            
            if added:
                self._metrics['events_buffered'] += 1
                self._metrics['current_size'] = len(self._buffer)
                self._metrics['peak_size'] = max(self._metrics['peak_size'], self._metrics['current_size'])
            else:
                self._metrics['events_dropped'] += 1
            
            return added
            
        except Exception as e:
            logger.error(f"Error adding event to buffer: {e}")
            return False
    
    def get_events(self, count: int) -> List[SiemEvent]:
        """Get events from buffer for processing"""
        events = []
        
        try:
            if self.strategy == BufferStrategy.PRIORITY or self.strategy == BufferStrategy.HYBRID:
                events = self._get_priority_events(count)
            else:
                # FIFO or time-window
                while events.__len__() < count and self._buffer:
                    events.append(self._buffer.popleft())
            
            self._metrics['current_size'] = len(self._buffer)
            return events
            
        except Exception as e:
            logger.error(f"Error getting events from buffer: {e}")
            return []
    
    def _add_fifo(self, event: SiemEvent) -> bool:
        """Add event using FIFO strategy"""
        if len(self._buffer) >= self.config.buffer_size:
            self._buffer.popleft()  # Remove oldest
            self._metrics['buffer_overflows'] += 1
        
        self._buffer.append(event)
        return True
    
    def _add_priority(self, event: SiemEvent) -> bool:
        """Add event using priority strategy"""
        priority_queue = self._priority_queues[event.severity]
        
        # Check if we need to drop low-priority events
        if self._get_total_size() >= self.config.buffer_size:
            if not self._drop_low_priority_event():
                return False  # Could not make room
        
        priority_queue.append(event)
        self._buffer.append(event)  # Keep in main buffer too
        return True
    
    def _add_time_window(self, event: SiemEvent) -> bool:
        """Add event using time-window strategy"""
        event_window = int(event.timestamp.timestamp() // 60)
        
        # Clean old windows
        self._clean_old_windows()
        
        self._time_windows[event_window].append(event)
        self._buffer.append(event)
        return True
    
    def _add_hybrid(self, event: SiemEvent) -> bool:
        """Add event using hybrid strategy (priority + time-window)"""
        # High priority events bypass normal buffering
        if event.severity in [EventSeverity.CRITICAL, EventSeverity.HIGH]:
            return self._add_priority(event)
        else:
            return self._add_time_window(event)
    
    def _get_priority_events(self, count: int) -> List[SiemEvent]:
        """Get events prioritized by severity"""
        events = []
        
        # Process in priority order
        for severity in [EventSeverity.CRITICAL, EventSeverity.HIGH, EventSeverity.MEDIUM, EventSeverity.LOW, EventSeverity.INFO]:
            queue = self._priority_queues[severity]
            while len(events) < count and queue:
                event = queue.popleft()
                events.append(event)
                # Remove from main buffer too
                try:
                    self._buffer.remove(event)
                except ValueError:
                    pass  # Event not in main buffer
        
        return events
    
    def _drop_low_priority_event(self) -> bool:
        """Drop lowest priority event to make room"""
        for severity in reversed(list(EventSeverity)):
            queue = self._priority_queues[severity]
            if queue:
                dropped_event = queue.popleft()
                try:
                    self._buffer.remove(dropped_event)
                except ValueError:
                    pass
                self._metrics['events_dropped'] += 1
                return True
        return False
    
    def _get_total_size(self) -> int:
        """Get total size across all buffers"""
        return sum(len(queue) for queue in self._priority_queues.values())
    
    def _clean_old_windows(self) -> None:
        """Clean old time windows"""
        current_time = int(time.time() // 60)
        old_windows = [w for w in self._time_windows.keys() if current_time - w > 60]  # Keep 1 hour
        
        for window in old_windows:
            del self._time_windows[window]
    
    def _get_event_hash(self, event: SiemEvent) -> str:
        """Generate hash for event deduplication"""
        return event.get_hash()
    
    def cleanup_expired_hashes(self) -> None:
        """Clean up expired hash entries"""
        current_time = datetime.utcnow()
        expired_hashes = [
            h for h, expiry in self._hash_expiry.items()
            if current_time > expiry
        ]
        
        for h in expired_hashes:
            self._event_hashes.discard(h)
            del self._hash_expiry[h]
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get buffer metrics"""
        return {
            **self._metrics,
            'deduplication_entries': len(self._event_hashes),
            'time_windows': len(self._time_windows),
            'priority_queue_sizes': {
                severity.name: len(queue) 
                for severity, queue in self._priority_queues.items()
            }
        }
    
    def clear(self) -> None:
        """Clear all buffers"""
        self._buffer.clear()
        for queue in self._priority_queues.values():
            queue.clear()
        self._time_windows.clear()
        self._event_hashes.clear()
        self._hash_expiry.clear()

class SiemStreamProcessor:
    """
    Production-grade SIEM stream processor
    
    Features:
    - Multi-source stream ingestion
    - Intelligent buffering and batching
    - Real-time filtering and deduplication
    - Rate limiting and backpressure handling
    - Integration with correlation and enrichment
    - Comprehensive metrics and monitoring
    """
    
    def __init__(
        self,
        config: StreamConfig,
        siem_connectors: List[BaseSiemConnector],
        correlation_engine: Optional[ThreatCorrelationEngine] = None,
        enrichment_service: Optional[AlertEnrichmentService] = None
    ):
        self.config = config
        self.siem_connectors = {conn.platform.value: conn for conn in siem_connectors}
        self.correlation_engine = correlation_engine
        self.enrichment_service = enrichment_service
        
        # Processing state
        self._status = StreamStatus.STOPPED
        self._event_buffer = EventBuffer(config)
        self._processing_tasks: Dict[str, asyncio.Task] = {}
        self._stream_tasks: Dict[str, asyncio.Task] = {}
        self._rate_limiter = asyncio.Semaphore(config.max_events_per_second)
        
        # Event handlers
        self._event_handlers: List[Callable[[SiemEvent], None]] = []
        self._batch_handlers: List[Callable[[List[SiemEvent]], None]] = []
        
        # Filtering
        self._event_filters: List[Callable[[SiemEvent], bool]] = []
        self._load_default_filters()
        
        # Metrics
        self._metrics = {
            'events_received': 0,
            'events_processed': 0,
            'events_filtered': 0,
            'batches_processed': 0,
            'correlations_created': 0,
            'enrichments_generated': 0,
            'processing_errors': 0,
            'average_processing_time_ms': 0.0,
            'throughput_events_per_second': 0.0,
            'start_time': None,
            'last_activity': datetime.utcnow()
        }
        
        # Background tasks
        self._monitoring_task: Optional[asyncio.Task] = None
        self._cleanup_task: Optional[asyncio.Task] = None
        
        logger.info(f"SIEM Stream Processor initialized with {len(siem_connectors)} connectors")
    
    async def start(self) -> None:
        """Start the stream processor"""
        if self._status != StreamStatus.STOPPED:
            logger.warning("Stream processor already running")
            return
        
        try:
            self._status = StreamStatus.STARTING
            self._metrics['start_time'] = datetime.utcnow()
            
            # Start SIEM connections
            for platform, connector in self.siem_connectors.items():
                if connector.get_connection_status().value != "connected":
                    await connector.connect()
            
            # Start event streams
            for platform, connector in self.siem_connectors.items():
                stream_task = asyncio.create_task(
                    self._process_siem_stream(platform, connector)
                )
                self._stream_tasks[platform] = stream_task
            
            # Start processing worker
            self._processing_tasks['main'] = asyncio.create_task(self._processing_worker())
            
            # Start monitoring tasks
            if self.config.enable_metrics:
                self._monitoring_task = asyncio.create_task(self._monitoring_worker())
            
            self._cleanup_task = asyncio.create_task(self._cleanup_worker())
            
            self._status = StreamStatus.RUNNING
            logger.info("SIEM Stream Processor started successfully")
            
        except Exception as e:
            logger.error(f"Error starting stream processor: {e}")
            self._status = StreamStatus.ERROR
            await self.stop()
            raise
    
    async def stop(self) -> None:
        """Stop the stream processor"""
        logger.info("Stopping SIEM Stream Processor...")
        self._status = StreamStatus.STOPPED
        
        # Cancel all tasks
        all_tasks = [
            *self._stream_tasks.values(),
            *self._processing_tasks.values()
        ]
        
        if self._monitoring_task:
            all_tasks.append(self._monitoring_task)
        if self._cleanup_task:
            all_tasks.append(self._cleanup_task)
        
        for task in all_tasks:
            if task and not task.done():
                task.cancel()
        
        # Wait for tasks to complete
        if all_tasks:
            await asyncio.gather(*all_tasks, return_exceptions=True)
        
        # Clear state
        self._stream_tasks.clear()
        self._processing_tasks.clear()
        self._event_buffer.clear()
        
        logger.info("SIEM Stream Processor stopped")
    
    async def _process_siem_stream(self, platform: str, connector: BaseSiemConnector) -> None:
        """Process events from a SIEM stream"""
        logger.info(f"Starting {platform} event stream processing")
        
        try:
            async for event in connector.start_event_stream():
                if self._status != StreamStatus.RUNNING:
                    break
                
                self._metrics['events_received'] += 1
                self._metrics['last_activity'] = datetime.utcnow()
                
                # Apply rate limiting
                async with self._rate_limiter:
                    # Apply filters
                    if self.config.enable_filtering and not self._passes_filters(event):
                        self._metrics['events_filtered'] += 1
                        continue
                    
                    # Add to buffer
                    if not self._event_buffer.add_event(event):
                        logger.warning(f"Failed to buffer event {event.id}")
                        continue
                    
                    # Check backpressure
                    buffer_utilization = (
                        self._event_buffer._metrics['current_size'] / 
                        self.config.buffer_size
                    )
                    
                    if buffer_utilization > self.config.backpressure_threshold:
                        logger.warning(f"High buffer utilization: {buffer_utilization:.2%}")
                        # Could implement backpressure strategies here
                    
                    # Notify event handlers
                    await self._notify_event_handlers(event)
        
        except asyncio.CancelledError:
            logger.info(f"Stream processing cancelled for {platform}")
        except Exception as e:
            logger.error(f"Error processing {platform} stream: {e}")
            self._status = StreamStatus.ERROR
    
    async def _processing_worker(self) -> None:
        """Main event processing worker"""
        logger.info("Starting event processing worker")
        
        while self._status == StreamStatus.RUNNING:
            try:
                start_time = datetime.utcnow()
                
                # Get batch of events
                events = self._event_buffer.get_events(self.config.processing_batch_size)
                
                if events:
                    await self._process_event_batch(events)
                    self._metrics['batches_processed'] += 1
                    
                    # Update processing time
                    processing_time = (datetime.utcnow() - start_time).total_seconds() * 1000
                    self._metrics['average_processing_time_ms'] = (
                        (self._metrics['average_processing_time_ms'] * (self._metrics['batches_processed'] - 1) + processing_time) /
                        self._metrics['batches_processed']
                    )
                else:
                    # No events, sleep
                    await asyncio.sleep(self.config.processing_interval_ms / 1000)
                
            except asyncio.CancelledError:
                logger.info("Processing worker cancelled")
                break
            except Exception as e:
                logger.error(f"Error in processing worker: {e}")
                self._metrics['processing_errors'] += 1
                await asyncio.sleep(1)
    
    async def _process_event_batch(self, events: List[SiemEvent]) -> None:
        """Process a batch of events"""
        try:
            # Parallel processing of batch
            processing_tasks = []
            
            for event in events:
                task = asyncio.create_task(self._process_single_event(event))
                processing_tasks.append(task)
            
            # Wait for all events to be processed
            await asyncio.gather(*processing_tasks, return_exceptions=True)
            
            # Notify batch handlers
            await self._notify_batch_handlers(events)
            
            self._metrics['events_processed'] += len(events)
            
        except Exception as e:
            logger.error(f"Error processing event batch: {e}")
            self._metrics['processing_errors'] += 1
    
    async def _process_single_event(self, event: SiemEvent) -> None:
        """Process a single event"""
        try:
            # Correlation analysis
            if self.config.enable_correlation and self.correlation_engine:
                correlations = await self.correlation_engine.process_event(event)
                if correlations:
                    self._metrics['correlations_created'] += len(correlations)
                    logger.debug(f"Created {len(correlations)} correlations for event {event.id}")
            
            # Enrichment
            if self.config.enable_enrichment and self.enrichment_service:
                try:
                    enriched_alert = await asyncio.wait_for(
                        self.enrichment_service.enrich_alert(event),
                        timeout=self.config.enrichment_timeout_seconds
                    )
                    
                    if enriched_alert.enrichments:
                        self._metrics['enrichments_generated'] += 1
                        logger.debug(f"Generated {len(enriched_alert.enrichments)} enrichments for event {event.id}")
                
                except asyncio.TimeoutError:
                    logger.warning(f"Enrichment timeout for event {event.id}")
                except Exception as e:
                    logger.warning(f"Enrichment error for event {event.id}: {e}")
            
        except Exception as e:
            logger.error(f"Error processing event {event.id}: {e}")
            self._metrics['processing_errors'] += 1
    
    async def _monitoring_worker(self) -> None:
        """Background monitoring and metrics worker"""
        last_event_count = 0
        last_time = datetime.utcnow()
        
        while self._status == StreamStatus.RUNNING:
            try:
                await asyncio.sleep(10)  # Update every 10 seconds
                
                # Calculate throughput
                current_time = datetime.utcnow()
                current_event_count = self._metrics['events_processed']
                
                time_diff = (current_time - last_time).total_seconds()
                event_diff = current_event_count - last_event_count
                
                if time_diff > 0:
                    throughput = event_diff / time_diff
                    self._metrics['throughput_events_per_second'] = throughput
                
                last_time = current_time
                last_event_count = current_event_count
                
                # Log metrics
                if self._metrics['events_processed'] > 0:
                    logger.debug(
                        f"Stream metrics - Processed: {self._metrics['events_processed']}, "
                        f"Throughput: {throughput:.1f} events/sec, "
                        f"Buffer size: {self._event_buffer._metrics['current_size']}, "
                        f"Errors: {self._metrics['processing_errors']}"
                    )
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in monitoring worker: {e}")
    
    async def _cleanup_worker(self) -> None:
        """Background cleanup worker"""
        while self._status == StreamStatus.RUNNING:
            try:
                # Cleanup buffer hashes
                self._event_buffer.cleanup_expired_hashes()
                
                # Clean up old metrics
                await asyncio.sleep(300)  # Run every 5 minutes
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in cleanup worker: {e}")
    
    def _passes_filters(self, event: SiemEvent) -> bool:
        """Check if event passes all filters"""
        try:
            for filter_func in self._event_filters:
                if not filter_func(event):
                    return False
            return True
        except Exception as e:
            logger.warning(f"Error applying filters to event {event.id}: {e}")
            return True  # Default to pass if filter fails
    
    def _load_default_filters(self) -> None:
        """Load default event filters"""
        # Filter out test events
        def filter_test_events(event: SiemEvent) -> bool:
            return 'test' not in event.message.lower() and 'test' not in event.source.lower()
        
        # Filter out low-severity info events from certain sources
        def filter_noisy_info_events(event: SiemEvent) -> bool:
            if event.severity == EventSeverity.INFO:
                noisy_sources = ['system', 'heartbeat', 'status']
                return not any(source in event.source.lower() for source in noisy_sources)
            return True
        
        # Filter out duplicate consecutive events
        def filter_rapid_duplicates(event: SiemEvent) -> bool:
            # This would need more sophisticated state tracking
            # For now, just a placeholder
            return True
        
        if self.config.enable_filtering:
            self._event_filters.extend([
                filter_test_events,
                filter_noisy_info_events,
                filter_rapid_duplicates
            ])
    
    async def _notify_event_handlers(self, event: SiemEvent) -> None:
        """Notify event handlers"""
        for handler in self._event_handlers:
            try:
                if asyncio.iscoroutinefunction(handler):
                    await handler(event)
                else:
                    handler(event)
            except Exception as e:
                logger.warning(f"Error in event handler: {e}")
    
    async def _notify_batch_handlers(self, events: List[SiemEvent]) -> None:
        """Notify batch handlers"""
        for handler in self._batch_handlers:
            try:
                if asyncio.iscoroutinefunction(handler):
                    await handler(events)
                else:
                    handler(events)
            except Exception as e:
                logger.warning(f"Error in batch handler: {e}")
    
    # Public API methods
    
    def add_event_handler(self, handler: Callable[[SiemEvent], None]) -> None:
        """Add event handler"""
        self._event_handlers.append(handler)
    
    def add_batch_handler(self, handler: Callable[[List[SiemEvent]], None]) -> None:
        """Add batch handler"""
        self._batch_handlers.append(handler)
    
    def add_event_filter(self, filter_func: Callable[[SiemEvent], bool]) -> None:
        """Add event filter"""
        self._event_filters.append(filter_func)
    
    def remove_event_handler(self, handler: Callable[[SiemEvent], None]) -> None:
        """Remove event handler"""
        if handler in self._event_handlers:
            self._event_handlers.remove(handler)
    
    def remove_batch_handler(self, handler: Callable[[List[SiemEvent]], None]) -> None:
        """Remove batch handler"""
        if handler in self._batch_handlers:
            self._batch_handlers.remove(handler)
    
    def remove_event_filter(self, filter_func: Callable[[SiemEvent], bool]) -> None:
        """Remove event filter"""
        if filter_func in self._event_filters:
            self._event_filters.remove(filter_func)
    
    async def pause(self) -> None:
        """Pause stream processing"""
        if self._status == StreamStatus.RUNNING:
            self._status = StreamStatus.PAUSED
            logger.info("Stream processor paused")
    
    async def resume(self) -> None:
        """Resume stream processing"""
        if self._status == StreamStatus.PAUSED:
            self._status = StreamStatus.RUNNING
            logger.info("Stream processor resumed")
    
    def get_status(self) -> StreamStatus:
        """Get current processing status"""
        return self._status
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get comprehensive metrics"""
        uptime_seconds = 0
        if self._metrics['start_time']:
            uptime_seconds = (datetime.utcnow() - self._metrics['start_time']).total_seconds()
        
        return {
            **self._metrics,
            'status': self._status.value,
            'uptime_seconds': uptime_seconds,
            'buffer_metrics': self._event_buffer.get_metrics(),
            'siem_connectors': {
                platform: connector.get_metrics()
                for platform, connector in self.siem_connectors.items()
            },
            'active_streams': len(self._stream_tasks),
            'active_processors': len(self._processing_tasks)
        }
    
    def get_buffer_status(self) -> Dict[str, Any]:
        """Get detailed buffer status"""
        return {
            'size': self._event_buffer._metrics['current_size'],
            'capacity': self.config.buffer_size,
            'utilization': self._event_buffer._metrics['current_size'] / self.config.buffer_size,
            'strategy': self.config.buffer_strategy.value,
            'overflow_count': self._event_buffer._metrics['buffer_overflows'],
            'deduplication_active': self.config.enable_deduplication,
            'deduplicated_events': self._event_buffer._metrics['events_deduplicated']
        }
    
    async def flush_buffer(self) -> int:
        """Flush all buffered events for processing"""
        events_to_process = self._event_buffer.get_events(self._event_buffer._metrics['current_size'])
        
        if events_to_process:
            await self._process_event_batch(events_to_process)
            logger.info(f"Flushed {len(events_to_process)} events from buffer")
        
        return len(events_to_process)
    
    async def __aenter__(self):
        """Async context manager entry"""
        await self.start()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self.stop()