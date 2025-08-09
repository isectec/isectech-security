"""
Performance Optimization Module for Feature Engineering Pipeline.

This module provides advanced performance optimizations for the feature engineering pipeline
to achieve >10K events/second throughput with minimal memory footprint.

Performance Engineering Focus:
- Memory pool management and object reuse
- Vectorized operations and batch processing
- Async I/O optimization with connection pooling
- CPU-efficient data structures and algorithms
- Memory-mapped caching for large datasets
"""

import asyncio
import logging
import time
import gc
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple, AsyncGenerator, Callable
from collections import deque, defaultdict
import weakref
import mmap
import os
import pickle
from pathlib import Path

import numpy as np
import pandas as pd
import uvloop  # High-performance event loop
import aioredis
import aiokafka
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
import psutil
import orjson  # Fast JSON serialization

from .feature_engineering_pipeline import (
    FeatureEngineeringPipeline, 
    FeatureVector, 
    ComputedFeature,
    BehaviorEvent
)

logger = logging.getLogger(__name__)


@dataclass
class MemoryStats:
    """Memory usage statistics."""
    rss_mb: float
    vms_mb: float
    percent: float
    available_mb: float
    peak_usage_mb: float = 0.0
    allocation_count: int = 0


@dataclass
class PerformanceMetrics:
    """Performance metrics tracking."""
    events_processed: int = 0
    processing_time_ms: float = 0.0
    throughput_eps: float = 0.0
    memory_stats: MemoryStats = None
    cache_hit_rate: float = 0.0
    error_count: int = 0
    gc_collections: int = 0


class ObjectPool:
    """Generic object pool for memory reuse."""
    
    def __init__(self, factory: Callable, max_size: int = 1000):
        self.factory = factory
        self.max_size = max_size
        self._pool = deque(maxlen=max_size)
        self._in_use = weakref.WeakSet()
        self.created_count = 0
        self.reuse_count = 0
    
    def acquire(self):
        """Acquire object from pool."""
        if self._pool:
            obj = self._pool.popleft()
            self.reuse_count += 1
        else:
            obj = self.factory()
            self.created_count += 1
        
        self._in_use.add(obj)
        return obj
    
    def release(self, obj):
        """Return object to pool."""
        if obj in self._in_use:
            self._in_use.remove(obj)
            if len(self._pool) < self.max_size:
                # Reset object state if needed
                if hasattr(obj, 'reset'):
                    obj.reset()
                self._pool.append(obj)
    
    def stats(self) -> Dict[str, Any]:
        """Get pool statistics."""
        return {
            "pool_size": len(self._pool),
            "in_use": len(self._in_use),
            "created_count": self.created_count,
            "reuse_count": self.reuse_count,
            "reuse_ratio": self.reuse_count / (self.created_count + self.reuse_count) if (self.created_count + self.reuse_count) > 0 else 0
        }


class MemoryMappedCache:
    """Memory-mapped cache for large feature datasets."""
    
    def __init__(self, cache_dir: str = "/tmp/feature_cache", max_size_mb: int = 1024):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)
        self.max_size_mb = max_size_mb
        self.cache_files = {}
        self.access_times = {}
        self.total_size_mb = 0
    
    def _get_cache_path(self, key: str) -> Path:
        """Get cache file path for key."""
        safe_key = key.replace('/', '_').replace(':', '_')
        return self.cache_dir / f"cache_{safe_key}.dat"
    
    async def set(self, key: str, data: Any, ttl_seconds: int = 3600) -> None:
        """Store data in memory-mapped cache."""
        try:
            cache_path = self._get_cache_path(key)
            
            # Serialize data
            serialized_data = orjson.dumps(data)
            data_size_mb = len(serialized_data) / (1024 * 1024)
            
            # Check cache size limits
            await self._ensure_cache_space(data_size_mb)
            
            # Write to memory-mapped file
            with open(cache_path, 'wb') as f:
                f.write(serialized_data)
            
            self.cache_files[key] = {
                'path': cache_path,
                'size_mb': data_size_mb,
                'created_at': time.time(),
                'ttl_seconds': ttl_seconds
            }
            self.access_times[key] = time.time()
            self.total_size_mb += data_size_mb
            
        except Exception as e:
            logger.error(f"Failed to cache data for key {key}: {str(e)}")
    
    async def get(self, key: str) -> Optional[Any]:
        """Retrieve data from memory-mapped cache."""
        try:
            if key not in self.cache_files:
                return None
            
            cache_info = self.cache_files[key]
            
            # Check TTL
            if time.time() - cache_info['created_at'] > cache_info['ttl_seconds']:
                await self._remove_cache_entry(key)
                return None
            
            # Memory-map and read
            cache_path = cache_info['path']
            if not cache_path.exists():
                await self._remove_cache_entry(key)
                return None
            
            with open(cache_path, 'rb') as f:
                with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mmapped_file:
                    data = orjson.loads(mmapped_file.read())
            
            # Update access time
            self.access_times[key] = time.time()
            return data
            
        except Exception as e:
            logger.error(f"Failed to retrieve cached data for key {key}: {str(e)}")
            return None
    
    async def _ensure_cache_space(self, required_mb: float) -> None:
        """Ensure sufficient cache space by evicting old entries."""
        while self.total_size_mb + required_mb > self.max_size_mb and self.cache_files:
            # Find least recently accessed item
            oldest_key = min(self.access_times.keys(), key=lambda k: self.access_times[k])
            await self._remove_cache_entry(oldest_key)
    
    async def _remove_cache_entry(self, key: str) -> None:
        """Remove cache entry and its file."""
        if key in self.cache_files:
            cache_info = self.cache_files[key]
            try:
                if cache_info['path'].exists():
                    cache_info['path'].unlink()
            except Exception as e:
                logger.error(f"Failed to remove cache file for key {key}: {str(e)}")
            
            self.total_size_mb -= cache_info['size_mb']
            del self.cache_files[key]
            
        if key in self.access_times:
            del self.access_times[key]
    
    async def cleanup(self) -> None:
        """Cleanup all cache files."""
        for key in list(self.cache_files.keys()):
            await self._remove_cache_entry(key)


class VectorizedFeatureProcessor:
    """Vectorized feature processing for batch operations."""
    
    def __init__(self):
        self.batch_processors = {
            'temporal': self._process_temporal_batch,
            'categorical': self._process_categorical_batch,
            'numerical': self._process_numerical_batch
        }
    
    def process_event_batch(self, events: List[BehaviorEvent]) -> pd.DataFrame:
        """Process batch of events using vectorized operations."""
        if not events:
            return pd.DataFrame()
        
        # Convert events to DataFrame for vectorized processing
        event_data = []
        for event in events:
            event_dict = {
                'event_id': event.event_id,
                'user_id': event.user_id,
                'session_id': event.session_id,
                'timestamp': event.timestamp,
                'event_type': event.event_type,
                'source': event.source,
                **event.data,
                **(event.device_info or {}),
                **(event.location_info or {})
            }
            event_data.append(event_dict)
        
        df = pd.DataFrame(event_data)
        
        # Apply vectorized feature extraction
        feature_df = pd.DataFrame(index=df.index)
        
        # Temporal features
        temporal_features = self._process_temporal_batch(df)
        feature_df = pd.concat([feature_df, temporal_features], axis=1)
        
        # Categorical features
        categorical_features = self._process_categorical_batch(df)
        feature_df = pd.concat([feature_df, categorical_features], axis=1)
        
        # Numerical features
        numerical_features = self._process_numerical_batch(df)
        feature_df = pd.concat([feature_df, numerical_features], axis=1)
        
        return feature_df
    
    def _process_temporal_batch(self, df: pd.DataFrame) -> pd.DataFrame:
        """Process temporal features in batch."""
        temporal_df = pd.DataFrame(index=df.index)
        
        # Extract temporal components
        timestamps = pd.to_datetime(df['timestamp'])
        temporal_df['hour_of_day'] = timestamps.dt.hour
        temporal_df['day_of_week'] = timestamps.dt.dayofweek
        temporal_df['is_weekend'] = timestamps.dt.dayofweek >= 5
        temporal_df['is_business_hours'] = (
            (timestamps.dt.hour >= 9) & 
            (timestamps.dt.hour <= 17) & 
            (timestamps.dt.dayofweek < 5)
        )
        
        # Month and quarter features
        temporal_df['month'] = timestamps.dt.month
        temporal_df['quarter'] = timestamps.dt.quarter
        
        # Time-based cyclical features (better for ML)
        temporal_df['hour_sin'] = np.sin(2 * np.pi * timestamps.dt.hour / 24)
        temporal_df['hour_cos'] = np.cos(2 * np.pi * timestamps.dt.hour / 24)
        temporal_df['day_sin'] = np.sin(2 * np.pi * timestamps.dt.dayofweek / 7)
        temporal_df['day_cos'] = np.cos(2 * np.pi * timestamps.dt.dayofweek / 7)
        
        return temporal_df
    
    def _process_categorical_batch(self, df: pd.DataFrame) -> pd.DataFrame:
        """Process categorical features in batch."""
        categorical_df = pd.DataFrame(index=df.index)
        
        # Device type encoding
        if 'device_type' in df.columns:
            device_dummies = pd.get_dummies(df['device_type'], prefix='device_type')
            categorical_df = pd.concat([categorical_df, device_dummies], axis=1)
        
        # Event type encoding
        if 'event_type' in df.columns:
            event_dummies = pd.get_dummies(df['event_type'], prefix='event_type')
            categorical_df = pd.concat([categorical_df, event_dummies], axis=1)
        
        # Country encoding (if available)
        if 'country' in df.columns:
            country_dummies = pd.get_dummies(df['country'], prefix='country')
            categorical_df = pd.concat([categorical_df, country_dummies], axis=1)
        
        # Source IP features
        if 'source_ip' in df.columns:
            # Extract IP features
            ip_parts = df['source_ip'].str.split('.', expand=True)
            if len(ip_parts.columns) >= 3:
                categorical_df['ip_class_c'] = ip_parts[0] + '.' + ip_parts[1] + '.' + ip_parts[2]
        
        return categorical_df
    
    def _process_numerical_batch(self, df: pd.DataFrame) -> pd.DataFrame:
        """Process numerical features in batch."""
        numerical_df = pd.DataFrame(index=df.index)
        
        # Response time features
        if 'duration_ms' in df.columns:
            duration = pd.to_numeric(df['duration_ms'], errors='coerce').fillna(0)
            numerical_df['duration_ms'] = duration
            numerical_df['duration_log'] = np.log1p(duration)
            numerical_df['duration_z_score'] = (duration - duration.mean()) / duration.std()
        
        # Data size features
        for col in ['request_size', 'response_size', 'file_size']:
            if col in df.columns:
                size_data = pd.to_numeric(df[col], errors='coerce').fillna(0)
                numerical_df[col] = size_data
                numerical_df[f'{col}_log'] = np.log1p(size_data)
        
        # Response code features
        if 'response_code' in df.columns:
            response_codes = pd.to_numeric(df['response_code'], errors='coerce').fillna(200)
            numerical_df['response_code'] = response_codes
            numerical_df['is_error'] = response_codes >= 400
            numerical_df['is_server_error'] = response_codes >= 500
        
        return numerical_df


class HighPerformanceFeaturePipeline:
    """High-performance optimized version of the feature engineering pipeline."""
    
    def __init__(self, 
                 redis_url: str = "redis://localhost:6379",
                 max_concurrent: int = 100,
                 batch_size: int = 500,
                 use_process_pool: bool = True,
                 cache_dir: str = "/tmp/feature_cache"):
        
        self.redis_url = redis_url
        self.max_concurrent = max_concurrent
        self.batch_size = batch_size
        self.use_process_pool = use_process_pool
        
        # Performance optimizations
        self.redis_pool = None
        self.memory_cache = MemoryMappedCache(cache_dir)
        self.vectorized_processor = VectorizedFeatureProcessor()
        
        # Object pools
        self.feature_vector_pool = ObjectPool(lambda: FeatureVector(
            user_id="", event_id="", timestamp=datetime.utcnow(), 
            features={}, total_computation_time_ms=0.0
        ))
        
        # Executor pools
        self.thread_pool = ThreadPoolExecutor(max_workers=min(32, os.cpu_count() + 4))
        if use_process_pool:
            self.process_pool = ProcessPoolExecutor(max_workers=os.cpu_count())
        else:
            self.process_pool = None
        
        # Performance metrics
        self.metrics = PerformanceMetrics()
        self.memory_peak = 0.0
        
        # Batch processing queues
        self.processing_queue = asyncio.Queue(maxsize=1000)
        self.result_queue = asyncio.Queue(maxsize=1000)
    
    async def initialize(self) -> None:
        """Initialize high-performance pipeline."""
        # Use uvloop for better async performance
        if hasattr(asyncio, 'set_event_loop_policy'):
            asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
        
        # Initialize Redis connection pool
        self.redis_pool = aioredis.ConnectionPool.from_url(
            self.redis_url,
            max_connections=self.max_concurrent * 2,
            retry_on_timeout=True,
            encoding="utf-8",
            decode_responses=True
        )
        
        # Start batch processing workers
        self.processing_tasks = [
            asyncio.create_task(self._batch_processing_worker(i))
            for i in range(min(4, os.cpu_count()))
        ]
        
        logger.info("High-Performance Feature Pipeline initialized")
    
    async def extract_features_high_throughput(self, events: List[BehaviorEvent]) -> List[FeatureVector]:
        """Extract features with high-throughput optimizations."""
        start_time = time.time()
        
        if not events:
            return []
        
        try:
            # Process in optimized batches
            results = []
            
            for i in range(0, len(events), self.batch_size):
                batch = events[i:i + self.batch_size]
                
                # Use vectorized processing for the batch
                batch_results = await self._process_batch_optimized(batch)
                results.extend(batch_results)
                
                # Memory management
                if i % (self.batch_size * 10) == 0:
                    await self._memory_cleanup()
            
            # Update metrics
            processing_time = (time.time() - start_time) * 1000
            self.metrics.events_processed += len(events)
            self.metrics.processing_time_ms += processing_time
            self.metrics.throughput_eps = len(events) / (processing_time / 1000) if processing_time > 0 else 0
            
            # Update memory stats
            await self._update_memory_stats()
            
            return results
            
        except Exception as e:
            logger.error(f"High-throughput feature extraction failed: {str(e)}")
            self.metrics.error_count += 1
            return []
    
    async def _process_batch_optimized(self, batch: List[BehaviorEvent]) -> List[FeatureVector]:
        """Process batch with optimizations."""
        batch_start = time.time()
        
        # Use vectorized processing
        if self.use_process_pool and self.process_pool:
            # CPU-intensive processing in separate process
            future = self.process_pool.submit(
                self._process_batch_cpu_intensive, 
                [self._serialize_event(e) for e in batch]
            )
            
            # Wait for result with timeout
            try:
                vectorized_features = await asyncio.wait_for(
                    asyncio.wrap_future(future), 
                    timeout=30.0
                )
            except asyncio.TimeoutError:
                logger.warning("Batch processing timeout, falling back to sync processing")
                vectorized_features = self.vectorized_processor.process_event_batch(batch)
        else:
            vectorized_features = self.vectorized_processor.process_event_batch(batch)
        
        # Convert to FeatureVector objects
        feature_vectors = []
        for i, event in enumerate(batch):
            if i < len(vectorized_features):
                fv = self.feature_vector_pool.acquire()
                fv.user_id = event.user_id
                fv.event_id = event.event_id
                fv.timestamp = event.timestamp
                fv.features = self._convert_row_to_features(vectorized_features.iloc[i])
                fv.total_computation_time_ms = (time.time() - batch_start) * 1000
                fv.feature_quality_score = self._calculate_quality_score(fv.features)
                feature_vectors.append(fv)
        
        return feature_vectors
    
    def _process_batch_cpu_intensive(self, serialized_events: List[Dict]) -> pd.DataFrame:
        """CPU-intensive batch processing in separate process."""
        # Deserialize events
        events = [self._deserialize_event(e) for e in serialized_events]
        
        # Process with vectorized processor
        return self.vectorized_processor.process_event_batch(events)
    
    def _serialize_event(self, event: BehaviorEvent) -> Dict:
        """Serialize event for process pool."""
        return {
            'event_id': event.event_id,
            'user_id': event.user_id,
            'session_id': event.session_id,
            'timestamp': event.timestamp.isoformat(),
            'event_type': event.event_type,
            'source': event.source,
            'data': event.data,
            'device_info': event.device_info,
            'location_info': event.location_info
        }
    
    def _deserialize_event(self, data: Dict) -> BehaviorEvent:
        """Deserialize event from process pool."""
        return BehaviorEvent(
            event_id=data['event_id'],
            user_id=data['user_id'],
            session_id=data['session_id'],
            timestamp=datetime.fromisoformat(data['timestamp']),
            event_type=data['event_type'],
            source=data['source'],
            data=data['data'],
            device_info=data['device_info'],
            location_info=data['location_info']
        )
    
    def _convert_row_to_features(self, row: pd.Series) -> Dict[str, ComputedFeature]:
        """Convert pandas row to ComputedFeature dictionary."""
        features = {}
        
        for feature_name, value in row.items():
            if pd.isna(value):
                continue
                
            # Determine feature type
            if feature_name.startswith(('hour_', 'day_', 'month_')):
                feature_type = 'temporal'
            elif feature_name.startswith(('device_', 'event_', 'country_')):
                feature_type = 'categorical'
            else:
                feature_type = 'numerical'
            
            features[feature_name] = ComputedFeature(
                name=feature_name,
                value=value,
                feature_type=feature_type,
                computation_time_ms=0.1,  # Negligible for vectorized operations
                timestamp=datetime.utcnow(),
                confidence=1.0
            )
        
        return features
    
    def _calculate_quality_score(self, features: Dict[str, ComputedFeature]) -> float:
        """Calculate feature quality score."""
        if not features:
            return 0.0
        
        # Simple quality score based on feature completeness
        expected_feature_count = 20  # Expected number of features
        completeness = min(len(features) / expected_feature_count, 1.0)
        
        return completeness
    
    async def _batch_processing_worker(self, worker_id: int) -> None:
        """Background worker for batch processing."""
        while True:
            try:
                # Get batch from queue
                batch = await self.processing_queue.get()
                
                if batch is None:  # Shutdown signal
                    break
                
                # Process batch
                results = await self._process_batch_optimized(batch)
                
                # Put results in result queue
                await self.result_queue.put(results)
                
                self.processing_queue.task_done()
                
            except Exception as e:
                logger.error(f"Batch processing worker {worker_id} error: {str(e)}")
                await asyncio.sleep(1)
    
    async def _memory_cleanup(self) -> None:
        """Perform memory cleanup and garbage collection."""
        # Force garbage collection
        gc.collect()
        
        # Update metrics
        await self._update_memory_stats()
        
        # Log memory usage if high
        if self.metrics.memory_stats and self.metrics.memory_stats.percent > 80:
            logger.warning(f"High memory usage: {self.metrics.memory_stats.percent:.1f}%")
    
    async def _update_memory_stats(self) -> None:
        """Update memory usage statistics."""
        try:
            process = psutil.Process()
            memory_info = process.memory_info()
            virtual_memory = psutil.virtual_memory()
            
            current_rss_mb = memory_info.rss / (1024 * 1024)
            self.memory_peak = max(self.memory_peak, current_rss_mb)
            
            self.metrics.memory_stats = MemoryStats(
                rss_mb=current_rss_mb,
                vms_mb=memory_info.vms / (1024 * 1024),
                percent=virtual_memory.percent,
                available_mb=virtual_memory.available / (1024 * 1024),
                peak_usage_mb=self.memory_peak
            )
            
        except Exception as e:
            logger.error(f"Failed to update memory stats: {str(e)}")
    
    async def get_performance_metrics(self) -> PerformanceMetrics:
        """Get comprehensive performance metrics."""
        await self._update_memory_stats()
        
        # Add object pool stats
        self.metrics.cache_hit_rate = self.feature_vector_pool.stats()['reuse_ratio']
        
        return self.metrics
    
    async def cleanup(self) -> None:
        """Cleanup resources and stop workers."""
        # Stop processing workers
        for _ in self.processing_tasks:
            await self.processing_queue.put(None)
        
        # Wait for workers to finish
        if hasattr(self, 'processing_tasks'):
            await asyncio.gather(*self.processing_tasks, return_exceptions=True)
        
        # Cleanup executor pools
        if self.thread_pool:
            self.thread_pool.shutdown(wait=True)
        
        if self.process_pool:
            self.process_pool.shutdown(wait=True)
        
        # Cleanup Redis pool
        if self.redis_pool:
            await self.redis_pool.disconnect()
        
        # Cleanup memory-mapped cache
        await self.memory_cache.cleanup()
        
        logger.info("High-Performance Feature Pipeline cleanup completed")


class FeaturePipelineOptimizer:
    """Optimizer for feature pipeline performance tuning."""
    
    def __init__(self, pipeline: HighPerformanceFeaturePipeline):
        self.pipeline = pipeline
        self.optimization_history = []
    
    async def optimize_for_throughput(self, target_eps: int = 10000) -> Dict[str, Any]:
        """Optimize pipeline configuration for target throughput."""
        logger.info(f"Optimizing pipeline for {target_eps} events/second")
        
        optimization_results = {
            "target_eps": target_eps,
            "optimizations_applied": [],
            "final_performance": None,
            "recommendations": []
        }
        
        # Test current performance
        baseline_perf = await self._benchmark_performance()
        optimization_results["baseline_performance"] = baseline_perf
        
        # Optimization strategies
        if baseline_perf["throughput_eps"] < target_eps:
            # Increase batch size
            if self.pipeline.batch_size < 1000:
                self.pipeline.batch_size = min(1000, self.pipeline.batch_size * 2)
                optimization_results["optimizations_applied"].append("Increased batch size")
            
            # Increase concurrency
            if self.pipeline.max_concurrent < 200:
                self.pipeline.max_concurrent = min(200, self.pipeline.max_concurrent * 1.5)
                optimization_results["optimizations_applied"].append("Increased concurrency")
            
            # Enable process pool if not already
            if not self.pipeline.use_process_pool:
                self.pipeline.use_process_pool = True
                optimization_results["optimizations_applied"].append("Enabled process pool")
        
        # Test optimized performance
        optimized_perf = await self._benchmark_performance()
        optimization_results["final_performance"] = optimized_perf
        
        # Generate recommendations
        if optimized_perf["throughput_eps"] < target_eps:
            optimization_results["recommendations"].extend([
                "Consider horizontal scaling with multiple pipeline instances",
                "Implement feature precomputation for frequently accessed features",
                "Optimize Redis configuration for higher throughput",
                "Consider using dedicated feature processing servers"
            ])
        
        return optimization_results
    
    async def optimize_for_latency(self, target_latency_ms: float = 50.0) -> Dict[str, Any]:
        """Optimize pipeline configuration for target latency."""
        logger.info(f"Optimizing pipeline for {target_latency_ms}ms latency")
        
        optimization_results = {
            "target_latency_ms": target_latency_ms,
            "optimizations_applied": [],
            "final_performance": None,
            "recommendations": []
        }
        
        baseline_perf = await self._benchmark_performance()
        optimization_results["baseline_performance"] = baseline_perf
        
        # Latency optimization strategies
        if baseline_perf.get("average_latency_ms", 100) > target_latency_ms:
            # Reduce batch size for lower latency
            if self.pipeline.batch_size > 100:
                self.pipeline.batch_size = max(100, self.pipeline.batch_size // 2)
                optimization_results["optimizations_applied"].append("Reduced batch size")
            
            # Optimize for single-threaded processing for latency-sensitive operations
            if self.pipeline.use_process_pool:
                self.pipeline.use_process_pool = False
                optimization_results["optimizations_applied"].append("Disabled process pool for latency")
        
        optimized_perf = await self._benchmark_performance()
        optimization_results["final_performance"] = optimized_perf
        
        if optimized_perf.get("average_latency_ms", 100) > target_latency_ms:
            optimization_results["recommendations"].extend([
                "Implement feature caching with longer TTL",
                "Pre-compute features for active users",
                "Use in-memory feature store",
                "Implement feature approximation algorithms"
            ])
        
        return optimization_results
    
    async def _benchmark_performance(self, event_count: int = 1000) -> Dict[str, Any]:
        """Benchmark current pipeline performance."""
        from .feature_pipeline_testing import MockDataGenerator
        
        data_generator = MockDataGenerator()
        events = data_generator.generate_event_batch(event_count)
        
        start_time = time.time()
        start_memory = psutil.Process().memory_info().rss / (1024 * 1024)
        
        try:
            results = await self.pipeline.extract_features_high_throughput(events)
            
            end_time = time.time()
            end_memory = psutil.Process().memory_info().rss / (1024 * 1024)
            
            duration = end_time - start_time
            throughput_eps = len(results) / duration if duration > 0 else 0
            
            return {
                "events_processed": len(results),
                "duration_seconds": duration,
                "throughput_eps": throughput_eps,
                "average_latency_ms": (duration * 1000) / len(results) if results else 0,
                "memory_usage_mb": end_memory - start_memory,
                "success_rate": (len(results) / event_count * 100) if event_count > 0 else 0
            }
            
        except Exception as e:
            logger.error(f"Performance benchmark failed: {str(e)}")
            return {
                "events_processed": 0,
                "duration_seconds": 0,
                "throughput_eps": 0,
                "average_latency_ms": float('inf'),
                "memory_usage_mb": 0,
                "success_rate": 0,
                "error": str(e)
            }


# Factory function for optimized pipeline
async def create_optimized_feature_pipeline(**config) -> HighPerformanceFeaturePipeline:
    """Create optimized high-performance feature pipeline."""
    pipeline = HighPerformanceFeaturePipeline(
        redis_url=config.get('redis_url', 'redis://localhost:6379'),
        max_concurrent=config.get('max_concurrent', 100),
        batch_size=config.get('batch_size', 500),
        use_process_pool=config.get('use_process_pool', True),
        cache_dir=config.get('cache_dir', '/tmp/feature_cache')
    )
    
    await pipeline.initialize()
    
    logger.info(f"Optimized Feature Pipeline created with batch_size={pipeline.batch_size}, "
               f"max_concurrent={pipeline.max_concurrent}")
    
    return pipeline


# Example usage and performance testing
if __name__ == "__main__":
    async def test_optimized_pipeline():
        from .feature_pipeline_testing import MockDataGenerator
        
        # Create optimized pipeline
        pipeline = await create_optimized_feature_pipeline(
            batch_size=1000,
            max_concurrent=200,
            use_process_pool=True
        )
        
        # Generate test data
        data_generator = MockDataGenerator()
        events = data_generator.generate_event_batch(10000)  # 10K events
        
        logger.info(f"Testing with {len(events)} events")
        
        # Benchmark performance
        start_time = time.time()
        results = await pipeline.extract_features_high_throughput(events)
        duration = time.time() - start_time
        
        throughput = len(results) / duration
        
        logger.info(f"Processed {len(results)} events in {duration:.2f} seconds")
        logger.info(f"Throughput: {throughput:.0f} events/second")
        
        # Get performance metrics
        metrics = await pipeline.get_performance_metrics()
        logger.info(f"Memory usage: {metrics.memory_stats.rss_mb:.1f} MB")
        logger.info(f"Cache hit rate: {metrics.cache_hit_rate:.2%}")
        
        # Optimize for throughput
        optimizer = FeaturePipelineOptimizer(pipeline)
        optimization_result = await optimizer.optimize_for_throughput(target_eps=15000)
        
        logger.info("Optimization results:")
        for opt in optimization_result["optimizations_applied"]:
            logger.info(f"  - {opt}")
        
        # Cleanup
        await pipeline.cleanup()
    
    # Configure logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    
    # Run test
    asyncio.run(test_optimized_pipeline())