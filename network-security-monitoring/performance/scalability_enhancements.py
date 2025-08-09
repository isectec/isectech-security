#!/usr/bin/env python3
"""
iSECTECH NSM Scalability Enhancements
High-throughput optimizations and scalability improvements for Network Security Monitoring components
"""

import asyncio
import json
import logging
import multiprocessing
import queue
import time
import uuid
from collections import deque, defaultdict
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable, Union
from pathlib import Path
import threading
import os
import signal
import sys

import psutil
import redis
import yaml
from aiohttp import web, ClientSession, TCPConnector
import aiofiles
import uvloop
import msgpack
import lz4.frame
from prometheus_client import Counter, Histogram, Gauge, generate_latest


@dataclass
class ScalabilityConfig:
    """Scalability configuration parameters"""
    # Processing configuration
    max_workers: int = multiprocessing.cpu_count() * 2
    batch_size: int = 1000
    buffer_size: int = 10000
    queue_timeout: float = 1.0
    
    # Memory management
    max_memory_usage: float = 0.8  # 80% of available memory
    gc_threshold: int = 50000  # Objects before garbage collection
    
    # Network configuration
    max_connections: int = 1000
    connection_pool_size: int = 100
    keepalive_timeout: int = 30
    
    # Caching configuration
    cache_size: int = 100000
    cache_ttl: int = 3600  # 1 hour
    
    # Auto-scaling configuration
    scale_up_threshold: float = 0.8  # 80% utilization
    scale_down_threshold: float = 0.3  # 30% utilization
    min_workers: int = 2
    max_workers_limit: int = 50


@dataclass
class ThroughputMetrics:
    """Throughput and performance metrics"""
    component: str
    timestamp: datetime
    events_per_second: float
    bytes_per_second: float
    cpu_utilization: float
    memory_utilization: float
    queue_depth: int
    processing_latency: float
    error_rate: float
    worker_count: int


class HighThroughputBuffer:
    """High-performance circular buffer for event processing"""
    
    def __init__(self, size: int = 100000):
        self.size = size
        self.buffer = [None] * size
        self.head = 0
        self.tail = 0
        self.count = 0
        self.lock = threading.RLock()
        
    def put(self, item: Any) -> bool:
        """Add item to buffer, returns False if buffer is full"""
        with self.lock:
            if self.count >= self.size:
                return False
            
            self.buffer[self.tail] = item
            self.tail = (self.tail + 1) % self.size
            self.count += 1
            return True
    
    def get(self) -> Optional[Any]:
        """Get item from buffer, returns None if empty"""
        with self.lock:
            if self.count == 0:
                return None
            
            item = self.buffer[self.head]
            self.buffer[self.head] = None  # Clear reference
            self.head = (self.head + 1) % self.size
            self.count -= 1
            return item
    
    def get_batch(self, batch_size: int) -> List[Any]:
        """Get batch of items from buffer"""
        batch = []
        with self.lock:
            for _ in range(min(batch_size, self.count)):
                if self.count > 0:
                    item = self.buffer[self.head]
                    self.buffer[self.head] = None
                    self.head = (self.head + 1) % self.size
                    self.count -= 1
                    batch.append(item)
        return batch
    
    def is_full(self) -> bool:
        with self.lock:
            return self.count >= self.size
    
    def is_empty(self) -> bool:
        with self.lock:
            return self.count == 0
    
    def size_used(self) -> int:
        with self.lock:
            return self.count


class MemoryPool:
    """Memory pool for object reuse to reduce garbage collection"""
    
    def __init__(self, factory: Callable, initial_size: int = 100, max_size: int = 1000):
        self.factory = factory
        self.max_size = max_size
        self.pool = deque()
        self.lock = threading.RLock()
        
        # Pre-populate pool
        for _ in range(initial_size):
            self.pool.append(factory())
    
    def get(self):
        """Get object from pool"""
        with self.lock:
            if self.pool:
                return self.pool.popleft()
            else:
                return self.factory()
    
    def put(self, obj):
        """Return object to pool"""
        with self.lock:
            if len(self.pool) < self.max_size:
                # Reset object state if it has a reset method
                if hasattr(obj, 'reset'):
                    obj.reset()
                self.pool.append(obj)


class AdaptiveWorkerPool:
    """Auto-scaling worker pool that adjusts based on load"""
    
    def __init__(self, config: ScalabilityConfig, worker_func: Callable, logger: logging.Logger):
        self.config = config
        self.worker_func = worker_func
        self.logger = logger
        
        self.workers = []
        self.worker_count = config.min_workers
        self.running = False
        
        # Metrics
        self.processed_items = Counter()
        self.queue_sizes = deque(maxlen=100)
        self.cpu_usage = deque(maxlen=100)
        
        # Scaling controls
        self.last_scale_time = time.time()
        self.scale_cooldown = 60  # 1 minute cooldown
        
    def start(self):
        """Start the worker pool"""
        self.running = True
        self._spawn_workers(self.worker_count)
        
        # Start monitoring thread
        monitor_thread = threading.Thread(target=self._monitor_and_scale, daemon=True)
        monitor_thread.start()
        
        self.logger.info(f"Started adaptive worker pool with {self.worker_count} workers")
    
    def stop(self):
        """Stop the worker pool"""
        self.running = False
        
        # Wait for workers to finish
        for worker in self.workers:
            worker.join(timeout=5)
        
        self.logger.info("Stopped adaptive worker pool")
    
    def _spawn_workers(self, count: int):
        """Spawn worker threads"""
        for _ in range(count):
            worker = threading.Thread(target=self._worker_loop, daemon=True)
            worker.start()
            self.workers.append(worker)
    
    def _worker_loop(self):
        """Main worker loop"""
        while self.running:
            try:
                # Call the worker function
                processed = self.worker_func()
                if processed:
                    self.processed_items.inc(processed)
                else:
                    time.sleep(0.01)  # Brief sleep if no work
            except Exception as e:
                self.logger.error(f"Worker error: {e}")
                time.sleep(1)  # Error recovery delay
    
    def _monitor_and_scale(self):
        """Monitor performance and auto-scale workers"""
        while self.running:
            try:
                # Collect metrics
                cpu_percent = psutil.cpu_percent(interval=1)
                self.cpu_usage.append(cpu_percent)
                
                # Check if scaling is needed
                current_time = time.time()
                if current_time - self.last_scale_time > self.scale_cooldown:
                    self._check_scaling_conditions()
                
                time.sleep(10)  # Check every 10 seconds
                
            except Exception as e:
                self.logger.error(f"Monitor error: {e}")
                time.sleep(5)
    
    def _check_scaling_conditions(self):
        """Check if workers should be scaled up or down"""
        if len(self.cpu_usage) < 5:
            return  # Need sufficient data
        
        avg_cpu = sum(self.cpu_usage) / len(self.cpu_usage)
        
        # Scale up conditions
        if (avg_cpu > self.config.scale_up_threshold * 100 and 
            self.worker_count < self.config.max_workers_limit):
            
            new_count = min(self.worker_count + 2, self.config.max_workers_limit)
            self._spawn_workers(new_count - self.worker_count)
            self.worker_count = new_count
            self.last_scale_time = time.time()
            
            self.logger.info(f"Scaled up to {self.worker_count} workers (CPU: {avg_cpu:.1f}%)")
        
        # Scale down conditions
        elif (avg_cpu < self.config.scale_down_threshold * 100 and 
              self.worker_count > self.config.min_workers):
            
            new_count = max(self.worker_count - 1, self.config.min_workers)
            # Note: We don't actually terminate threads here, just reduce spawn count
            self.worker_count = new_count
            self.last_scale_time = time.time()
            
            self.logger.info(f"Scaled down to {self.worker_count} workers (CPU: {avg_cpu:.1f}%)")


class BatchProcessor:
    """High-throughput batch processing engine"""
    
    def __init__(self, config: ScalabilityConfig, processor_func: Callable, logger: logging.Logger):
        self.config = config
        self.processor_func = processor_func
        self.logger = logger
        
        # Processing buffers
        self.input_buffer = HighThroughputBuffer(config.buffer_size)
        self.output_buffer = HighThroughputBuffer(config.buffer_size)
        
        # Worker pool
        self.worker_pool = AdaptiveWorkerPool(config, self._process_batch, logger)
        
        # Metrics
        self.processed_batches = Counter()
        self.processing_time = Histogram('batch_processing_seconds', 'Batch processing time')
        self.buffer_utilization = Gauge('buffer_utilization', 'Buffer utilization percentage')
        
        # Control flags
        self.running = False
    
    def start(self):
        """Start batch processing"""
        self.running = True
        self.worker_pool.start()
        
        # Start buffer monitoring
        monitor_thread = threading.Thread(target=self._monitor_buffers, daemon=True)
        monitor_thread.start()
        
        self.logger.info("Started batch processor")
    
    def stop(self):
        """Stop batch processing"""
        self.running = False
        self.worker_pool.stop()
        self.logger.info("Stopped batch processor")
    
    def submit(self, item: Any) -> bool:
        """Submit item for processing"""
        return self.input_buffer.put(item)
    
    def get_result(self) -> Optional[Any]:
        """Get processed result"""
        return self.output_buffer.get()
    
    def get_results_batch(self, batch_size: int = None) -> List[Any]:
        """Get batch of processed results"""
        if batch_size is None:
            batch_size = self.config.batch_size
        return self.output_buffer.get_batch(batch_size)
    
    def _process_batch(self) -> int:
        """Process a batch of items"""
        batch = self.input_buffer.get_batch(self.config.batch_size)
        if not batch:
            return 0
        
        start_time = time.time()
        
        try:
            # Process batch
            results = self.processor_func(batch)
            
            # Store results
            if results:
                for result in results:
                    self.output_buffer.put(result)
            
            # Update metrics
            processing_time = time.time() - start_time
            self.processing_time.observe(processing_time)
            self.processed_batches.inc()
            
            return len(batch)
            
        except Exception as e:
            self.logger.error(f"Batch processing error: {e}")
            return 0
    
    def _monitor_buffers(self):
        """Monitor buffer utilization"""
        while self.running:
            try:
                input_util = (self.input_buffer.size_used() / self.input_buffer.size) * 100
                output_util = (self.output_buffer.size_used() / self.output_buffer.size) * 100
                
                self.buffer_utilization.labels(buffer='input').set(input_util)
                self.buffer_utilization.labels(buffer='output').set(output_util)
                
                # Log warnings for high utilization
                if input_util > 90:
                    self.logger.warning(f"Input buffer near capacity: {input_util:.1f}%")
                
                if output_util > 90:
                    self.logger.warning(f"Output buffer near capacity: {output_util:.1f}%")
                
                time.sleep(5)
                
            except Exception as e:
                self.logger.error(f"Buffer monitoring error: {e}")
                time.sleep(10)


class ConnectionPoolManager:
    """High-performance connection pool for external integrations"""
    
    def __init__(self, config: ScalabilityConfig, logger: logging.Logger):
        self.config = config
        self.logger = logger
        
        # HTTP session with connection pooling
        self.connector = TCPConnector(
            limit=config.max_connections,
            limit_per_host=config.connection_pool_size,
            keepalive_timeout=config.keepalive_timeout,
            enable_cleanup_closed=True
        )
        
        self.session = None
        self.redis_pool = None
        
    async def initialize(self):
        """Initialize connection pools"""
        # Initialize HTTP session
        self.session = ClientSession(
            connector=self.connector,
            timeout=aiohttp.ClientTimeout(total=30)
        )
        
        # Initialize Redis connection pool
        try:
            self.redis_pool = redis.ConnectionPool(
                host='localhost',
                port=6379,
                db=0,
                max_connections=self.config.connection_pool_size,
                retry_on_timeout=True,
                socket_keepalive=True,
                socket_keepalive_options={}
            )
            self.logger.info("Initialized connection pools")
        except Exception as e:
            self.logger.error(f"Failed to initialize Redis pool: {e}")
    
    async def close(self):
        """Close connection pools"""
        if self.session:
            await self.session.close()
        
        if self.redis_pool:
            self.redis_pool.disconnect()
        
        self.logger.info("Closed connection pools")
    
    async def make_request(self, method: str, url: str, **kwargs) -> Optional[Dict[str, Any]]:
        """Make HTTP request using connection pool"""
        try:
            async with self.session.request(method, url, **kwargs) as response:
                if response.status == 200:
                    return await response.json()
                else:
                    self.logger.warning(f"HTTP request failed: {response.status}")
                    return None
        except Exception as e:
            self.logger.error(f"HTTP request error: {e}")
            return None
    
    def get_redis_connection(self) -> Optional[redis.Redis]:
        """Get Redis connection from pool"""
        try:
            return redis.Redis(connection_pool=self.redis_pool)
        except Exception as e:
            self.logger.error(f"Redis connection error: {e}")
            return None


class CacheManager:
    """High-performance caching system with LRU eviction"""
    
    def __init__(self, config: ScalabilityConfig, logger: logging.Logger):
        self.config = config
        self.logger = logger
        
        # In-memory cache
        self.cache = {}
        self.access_times = {}
        self.lock = threading.RLock()
        
        # Redis cache
        self.redis_client = None
        
        # Metrics
        self.cache_hits = Counter('cache_hits_total', 'Cache hits')
        self.cache_misses = Counter('cache_misses_total', 'Cache misses')
        
    def initialize_redis(self, redis_client: redis.Redis):
        """Initialize Redis backend"""
        self.redis_client = redis_client
        self.logger.info("Initialized Redis cache backend")
    
    def get(self, key: str) -> Optional[Any]:
        """Get value from cache"""
        # Try in-memory cache first
        with self.lock:
            if key in self.cache:
                self.access_times[key] = time.time()
                self.cache_hits.inc()
                return self.cache[key]
        
        # Try Redis cache
        if self.redis_client:
            try:
                value = self.redis_client.get(f"nsm:cache:{key}")
                if value:
                    # Deserialize and store in memory cache
                    deserialized = msgpack.unpackb(lz4.frame.decompress(value))
                    self.set(key, deserialized, store_redis=False)
                    self.cache_hits.inc()
                    return deserialized
            except Exception as e:
                self.logger.debug(f"Redis cache get error: {e}")
        
        self.cache_misses.inc()
        return None
    
    def set(self, key: str, value: Any, ttl: int = None, store_redis: bool = True):
        """Set value in cache"""
        if ttl is None:
            ttl = self.config.cache_ttl
        
        # Store in memory cache
        with self.lock:
            # Evict if cache is full
            if len(self.cache) >= self.config.cache_size:
                self._evict_lru()
            
            self.cache[key] = value
            self.access_times[key] = time.time()
        
        # Store in Redis cache
        if self.redis_client and store_redis:
            try:
                # Serialize with compression
                serialized = lz4.frame.compress(msgpack.packb(value))
                self.redis_client.setex(f"nsm:cache:{key}", ttl, serialized)
            except Exception as e:
                self.logger.debug(f"Redis cache set error: {e}")
    
    def _evict_lru(self):
        """Evict least recently used items"""
        if not self.access_times:
            return
        
        # Find oldest accessed item
        oldest_key = min(self.access_times.keys(), key=lambda k: self.access_times[k])
        
        # Remove from cache
        del self.cache[oldest_key]
        del self.access_times[oldest_key]
    
    def clear(self):
        """Clear all caches"""
        with self.lock:
            self.cache.clear()
            self.access_times.clear()
        
        if self.redis_client:
            try:
                # Clear Redis cache keys
                keys = self.redis_client.keys("nsm:cache:*")
                if keys:
                    self.redis_client.delete(*keys)
            except Exception as e:
                self.logger.debug(f"Redis cache clear error: {e}")


class ScalabilityEnhancementFramework:
    """Main framework for NSM scalability enhancements"""
    
    def __init__(self, config_path: str = "/etc/nsm/scalability.yaml"):
        self.config_path = config_path
        self.config = self._load_config()
        self.logger = self._setup_logging()
        
        # Core components
        self.batch_processors = {}
        self.connection_manager = ConnectionPoolManager(self.config, self.logger)
        self.cache_manager = CacheManager(self.config, self.logger)
        
        # Metrics
        self.throughput_metrics = {}
        self.performance_counters = {
            'events_processed': Counter('events_processed_total', 'Total events processed'),
            'processing_errors': Counter('processing_errors_total', 'Processing errors'),
            'memory_usage': Gauge('memory_usage_bytes', 'Memory usage in bytes'),
            'worker_count': Gauge('active_workers', 'Number of active workers')
        }
        
        # Control flags
        self.running = False
        
    def _load_config(self) -> ScalabilityConfig:
        """Load scalability configuration"""
        try:
            with open(self.config_path, 'r') as f:
                config_data = yaml.safe_load(f)
                return ScalabilityConfig(**config_data)
        except Exception as e:
            print(f"Error loading scalability config: {e}, using defaults")
            return ScalabilityConfig()
    
    def _setup_logging(self) -> logging.Logger:
        """Setup logging configuration"""
        logger = logging.getLogger('ScalabilityEnhancementFramework')
        logger.setLevel(logging.INFO)
        
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        
        # File handler
        file_handler = logging.FileHandler('/var/log/nsm/scalability_enhancements.log')
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        
        return logger
    
    async def initialize(self):
        """Initialize scalability framework"""
        # Set uvloop as event loop policy for better performance
        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
        
        # Initialize connection pools
        await self.connection_manager.initialize()
        
        # Initialize Redis cache
        redis_client = self.connection_manager.get_redis_connection()
        if redis_client:
            self.cache_manager.initialize_redis(redis_client)
        
        self.logger.info("Scalability framework initialized")
    
    async def shutdown(self):
        """Shutdown scalability framework"""
        self.running = False
        
        # Stop batch processors
        for processor in self.batch_processors.values():
            processor.stop()
        
        # Close connections
        await self.connection_manager.close()
        
        self.logger.info("Scalability framework shutdown")
    
    def register_component_processor(self, component: str, processor_func: Callable):
        """Register a batch processor for a component"""
        processor = BatchProcessor(self.config, processor_func, self.logger)
        self.batch_processors[component] = processor
        
        self.logger.info(f"Registered batch processor for component: {component}")
    
    def start_component_processing(self, component: str):
        """Start processing for a component"""
        if component in self.batch_processors:
            self.batch_processors[component].start()
            self.logger.info(f"Started processing for component: {component}")
        else:
            raise ValueError(f"No processor registered for component: {component}")
    
    def submit_for_processing(self, component: str, item: Any) -> bool:
        """Submit item for processing by component"""
        if component in self.batch_processors:
            success = self.batch_processors[component].submit(item)
            if success:
                self.performance_counters['events_processed'].inc()
            else:
                self.performance_counters['processing_errors'].inc()
            return success
        return False
    
    def get_processed_results(self, component: str, batch_size: int = None) -> List[Any]:
        """Get processed results from component"""
        if component in self.batch_processors:
            return self.batch_processors[component].get_results_batch(batch_size)
        return []
    
    async def optimize_signature_detection(self, signatures: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Optimize signature detection processing"""
        def process_signature_batch(batch):
            results = []
            for signature_data in batch:
                try:
                    # Simulate signature processing optimization
                    # In real implementation, this would:
                    # 1. Vectorize signature matching
                    # 2. Use SIMD instructions for pattern matching
                    # 3. Implement multi-threaded rule evaluation
                    
                    optimized_signature = {
                        'signature_id': signature_data.get('signature_id'),
                        'pattern': signature_data.get('pattern'),
                        'optimized': True,
                        'processing_time': time.time(),
                        'confidence': signature_data.get('confidence', 0.0)
                    }
                    results.append(optimized_signature)
                except Exception as e:
                    self.logger.error(f"Signature processing error: {e}")
            
            return results
        
        # Register and start processor
        if 'signature_detection' not in self.batch_processors:
            self.register_component_processor('signature_detection', process_signature_batch)
            self.start_component_processing('signature_detection')
        
        # Submit signatures for processing
        for signature in signatures:
            self.submit_for_processing('signature_detection', signature)
        
        # Wait for processing and collect results
        await asyncio.sleep(1)  # Allow processing time
        return self.get_processed_results('signature_detection')
    
    async def optimize_anomaly_detection(self, network_flows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Optimize anomaly detection processing"""
        def process_anomaly_batch(batch):
            results = []
            for flow_data in batch:
                try:
                    # Simulate anomaly detection optimization
                    # In real implementation:
                    # 1. Use NumPy for vectorized statistical analysis
                    # 2. Implement sliding window algorithms efficiently
                    # 3. Use machine learning model batch inference
                    
                    anomaly_score = self._calculate_anomaly_score(flow_data)
                    
                    optimized_result = {
                        'flow_id': flow_data.get('flow_id'),
                        'anomaly_score': anomaly_score,
                        'is_anomalous': anomaly_score > 0.7,
                        'processing_time': time.time(),
                        'features': flow_data.get('features', {})
                    }
                    results.append(optimized_result)
                except Exception as e:
                    self.logger.error(f"Anomaly detection error: {e}")
            
            return results
        
        # Register and start processor
        if 'anomaly_detection' not in self.batch_processors:
            self.register_component_processor('anomaly_detection', process_anomaly_batch)
            self.start_component_processing('anomaly_detection')
        
        # Submit flows for processing
        for flow in network_flows:
            self.submit_for_processing('anomaly_detection', flow)
        
        # Wait for processing and collect results
        await asyncio.sleep(1)
        return self.get_processed_results('anomaly_detection')
    
    def _calculate_anomaly_score(self, flow_data: Dict[str, Any]) -> float:
        """Calculate anomaly score for network flow"""
        # Simplified anomaly scoring based on flow characteristics
        score = 0.0
        
        # Check packet size distribution
        packet_sizes = flow_data.get('packet_sizes', [])
        if packet_sizes:
            avg_size = sum(packet_sizes) / len(packet_sizes)
            if avg_size > 1400 or avg_size < 64:
                score += 0.2
        
        # Check timing patterns
        timing_intervals = flow_data.get('timing_intervals', [])
        if timing_intervals:
            # Look for regular beaconing patterns
            if len(set(int(t * 10) for t in timing_intervals)) < len(timing_intervals) * 0.5:
                score += 0.3
        
        # Check destination diversity
        dst_ips = flow_data.get('dst_ips', [])
        if len(dst_ips) > 10:  # Scanning behavior
            score += 0.4
        
        return min(score, 1.0)
    
    def get_throughput_metrics(self) -> Dict[str, ThroughputMetrics]:
        """Get current throughput metrics for all components"""
        metrics = {}
        
        for component, processor in self.batch_processors.items():
            # Calculate throughput metrics
            cpu_percent = psutil.cpu_percent()
            memory_info = psutil.virtual_memory()
            
            # Get component-specific metrics
            worker_count = processor.worker_pool.worker_count
            queue_depth = processor.input_buffer.size_used()
            
            # Estimate events per second (simplified)
            events_per_second = processor.processed_batches._value._value * self.config.batch_size / 60
            
            metrics[component] = ThroughputMetrics(
                component=component,
                timestamp=datetime.utcnow(),
                events_per_second=events_per_second,
                bytes_per_second=events_per_second * 1024,  # Rough estimate
                cpu_utilization=cpu_percent,
                memory_utilization=memory_info.percent,
                queue_depth=queue_depth,
                processing_latency=0.001,  # Placeholder
                error_rate=0.0,  # Placeholder
                worker_count=worker_count
            )
        
        return metrics
    
    def generate_optimization_report(self) -> str:
        """Generate scalability optimization report"""
        metrics = self.get_throughput_metrics()
        
        report = []
        report.append("=" * 80)
        report.append("NSM SCALABILITY OPTIMIZATION REPORT")
        report.append("=" * 80)
        report.append(f"Generated: {datetime.utcnow().isoformat()}")
        report.append(f"Active Components: {len(metrics)}")
        report.append("")
        
        # System overview
        cpu_percent = psutil.cpu_percent()
        memory = psutil.virtual_memory()
        
        report.append("SYSTEM OVERVIEW")
        report.append("-" * 40)
        report.append(f"CPU Utilization: {cpu_percent:.1f}%")
        report.append(f"Memory Utilization: {memory.percent:.1f}%")
        report.append(f"Available Memory: {memory.available / 1024 / 1024 / 1024:.1f} GB")
        report.append("")
        
        # Component metrics
        if metrics:
            report.append("COMPONENT THROUGHPUT METRICS")
            report.append("-" * 40)
            
            total_events_per_second = 0
            for component, metric in metrics.items():
                report.append(f"Component: {component}")
                report.append(f"  Events/sec: {metric.events_per_second:.1f}")
                report.append(f"  Workers: {metric.worker_count}")
                report.append(f"  Queue Depth: {metric.queue_depth}")
                report.append(f"  CPU Usage: {metric.cpu_utilization:.1f}%")
                report.append("")
                
                total_events_per_second += metric.events_per_second
            
            report.append(f"Total System Throughput: {total_events_per_second:.1f} events/sec")
            report.append("")
        
        # Optimization recommendations
        report.append("OPTIMIZATION RECOMMENDATIONS")
        report.append("-" * 40)
        
        recommendations = []
        
        if cpu_percent > 80:
            recommendations.append("• High CPU usage detected - consider scaling horizontally")
        
        if memory.percent > 85:
            recommendations.append("• High memory usage - consider increasing available memory")
        
        for component, metric in metrics.items():
            if metric.queue_depth > self.config.buffer_size * 0.8:
                recommendations.append(f"• {component}: Queue near capacity - increase buffer size")
            
            if metric.worker_count >= self.config.max_workers_limit * 0.9:
                recommendations.append(f"• {component}: Near worker limit - consider horizontal scaling")
        
        if not recommendations:
            report.append("✅ System performing optimally within current parameters")
        else:
            for rec in recommendations:
                report.append(rec)
        
        report.append("")
        report.append("=" * 80)
        
        return "\n".join(report)


async def main():
    """Main execution for scalability enhancements"""
    framework = ScalabilityEnhancementFramework()
    
    try:
        # Initialize framework
        await framework.initialize()
        
        # Example usage: optimize signature detection
        sample_signatures = [
            {
                'signature_id': f'sig_{i}',
                'pattern': f'pattern_{i}',
                'confidence': 0.8 + (i % 3) * 0.1
            }
            for i in range(1000)
        ]
        
        print("Testing signature detection optimization...")
        optimized_signatures = await framework.optimize_signature_detection(sample_signatures)
        print(f"Processed {len(optimized_signatures)} signatures")
        
        # Example usage: optimize anomaly detection
        sample_flows = [
            {
                'flow_id': f'flow_{i}',
                'packet_sizes': [64, 128, 256, 512, 1024],
                'timing_intervals': [0.1, 0.2, 0.1, 0.3, 0.1],
                'dst_ips': [f'192.168.1.{j}' for j in range(1, 5)]
            }
            for i in range(500)
        ]
        
        print("Testing anomaly detection optimization...")
        anomaly_results = await framework.optimize_anomaly_detection(sample_flows)
        print(f"Processed {len(anomaly_results)} network flows")
        
        # Generate and display optimization report
        report = framework.generate_optimization_report()
        print(report)
        
        # Save metrics
        metrics = framework.get_throughput_metrics()
        metrics_file = Path("/var/lib/nsm/scalability_metrics.json")
        metrics_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(metrics_file, 'w') as f:
            json.dump({k: asdict(v) for k, v in metrics.items()}, f, indent=2, default=str)
        
        print(f"Metrics saved to: {metrics_file}")
        
    except Exception as e:
        print(f"Scalability optimization failed: {e}")
        logging.exception("Scalability error")
    
    finally:
        await framework.shutdown()


if __name__ == "__main__":
    asyncio.run(main())