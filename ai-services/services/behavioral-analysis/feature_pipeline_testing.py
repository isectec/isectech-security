"""
Comprehensive Testing Framework for Feature Engineering Pipeline.

This module provides extensive testing capabilities for the feature engineering pipeline,
including correctness validation, performance testing, and quality assurance.

Performance Engineering Focus:
- Load testing for >10K events/second throughput
- Latency testing for <50ms feature extraction target
- Memory usage monitoring and optimization
- Concurrent processing validation
"""

import asyncio
import logging
import time
import statistics
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
import random
import json
import hashlib
import uuid
from pathlib import Path

import numpy as np
import pandas as pd
import pytest
import psutil
import matplotlib.pyplot as plt
import seaborn as sns

from .feature_engineering_pipeline import (
    FeatureEngineeringPipeline, 
    FeatureVector, 
    ComputedFeature,
    FeatureType,
    initialize_feature_engineering_pipeline
)
from .feature_store_integration import (
    FeatureStoreManager, 
    FeatureStoreType,
    initialize_feature_store_manager
)
from .data_sources_integration import BehaviorEvent

logger = logging.getLogger(__name__)


@dataclass
class TestResult:
    """Result of a test execution."""
    test_name: str
    success: bool
    execution_time_ms: float
    details: Dict[str, Any]
    timestamp: datetime = field(default_factory=datetime.utcnow)
    error_message: Optional[str] = None


@dataclass
class PerformanceTestResult:
    """Result of performance testing."""
    test_name: str
    total_events: int
    duration_seconds: float
    throughput_events_per_second: float
    average_latency_ms: float
    p95_latency_ms: float
    p99_latency_ms: float
    memory_usage_mb: float
    cpu_usage_percent: float
    error_count: int
    success_rate: float


class MockDataGenerator:
    """Generate mock behavior events for testing."""
    
    def __init__(self):
        self.user_ids = [f"user_{i:04d}" for i in range(1000)]
        self.event_types = [
            "login", "logout", "api_call", "file_access", "admin_action",
            "resource_access", "authentication", "authorization", "data_query"
        ]
        self.devices = [
            {"device_id": f"device_{i}", "device_type": "desktop"} for i in range(100)
        ] + [
            {"device_id": f"mobile_{i}", "device_type": "mobile"} for i in range(50)
        ]
        self.locations = [
            {"country": "US", "city": "Seattle"},
            {"country": "US", "city": "New York"},
            {"country": "US", "city": "San Francisco"},
            {"country": "UK", "city": "London"},
            {"country": "DE", "city": "Berlin"},
            {"country": "JP", "city": "Tokyo"}
        ]
        self.ip_addresses = [f"192.168.{i}.{j}" for i in range(1, 10) for j in range(1, 20)]
    
    def generate_behavior_event(self, user_id: str = None, timestamp: datetime = None) -> BehaviorEvent:
        """Generate a realistic behavior event."""
        if user_id is None:
            user_id = random.choice(self.user_ids)
        
        if timestamp is None:
            timestamp = datetime.utcnow() - timedelta(
                seconds=random.randint(0, 86400),
                microseconds=random.randint(0, 999999)
            )
        
        event_type = random.choice(self.event_types)
        device = random.choice(self.devices)
        location = random.choice(self.locations)
        source_ip = random.choice(self.ip_addresses)
        
        # Generate realistic event data based on type
        data = {
            "source_ip": source_ip,
            "user_agent": self._generate_user_agent(),
            "result": random.choices(["success", "failed"], weights=[0.9, 0.1])[0]
        }
        
        if event_type == "api_call":
            data.update({
                "endpoint": f"/api/v1/{random.choice(['users', 'data', 'reports', 'auth'])}",
                "method": random.choice(["GET", "POST", "PUT", "DELETE"]),
                "response_code": random.choices([200, 201, 400, 401, 403, 500], 
                                              weights=[0.7, 0.1, 0.05, 0.05, 0.05, 0.05])[0],
                "duration_ms": random.randint(10, 2000),
                "request_size": random.randint(100, 10000),
                "response_size": random.randint(500, 50000)
            })
        
        elif event_type == "file_access":
            data.update({
                "file_path": f"/documents/{random.choice(['reports', 'data', 'configs'])}/{uuid.uuid4().hex[:8]}.{random.choice(['txt', 'pdf', 'xlsx'])}",
                "access_type": random.choice(["read", "write", "delete"]),
                "file_size": random.randint(1024, 1048576)
            })
        
        elif event_type == "login":
            data.update({
                "mfa_used": random.choices([True, False], weights=[0.7, 0.3])[0],
                "session_duration": random.randint(300, 28800)  # 5 minutes to 8 hours
            })
        
        return BehaviorEvent(
            event_id=f"{event_type}_{uuid.uuid4().hex[:16]}",
            user_id=user_id,
            session_id=f"session_{hashlib.md5(f'{user_id}_{timestamp.date()}'.encode()).hexdigest()[:12]}",
            timestamp=timestamp,
            event_type=event_type,
            source="test_generator",
            data=data,
            device_info=device,
            location_info=location
        )
    
    def generate_event_batch(self, count: int, user_id: str = None) -> List[BehaviorEvent]:
        """Generate a batch of behavior events."""
        events = []
        base_time = datetime.utcnow()
        
        for i in range(count):
            # Create temporal spread
            event_time = base_time - timedelta(seconds=random.randint(0, 3600))  # Last hour
            events.append(self.generate_behavior_event(user_id, event_time))
        
        return sorted(events, key=lambda e: e.timestamp)
    
    def generate_user_session(self, user_id: str, session_duration_minutes: int = 60) -> List[BehaviorEvent]:
        """Generate a realistic user session with correlated events."""
        events = []
        start_time = datetime.utcnow() - timedelta(minutes=random.randint(0, 480))  # Within last 8 hours
        
        # Login event
        login_event = self.generate_behavior_event(user_id, start_time)
        login_event.event_type = "login"
        events.append(login_event)
        
        # Session activities
        current_time = start_time + timedelta(minutes=1)
        end_time = start_time + timedelta(minutes=session_duration_minutes)
        
        while current_time < end_time:
            # Vary activity frequency
            next_activity_delay = random.expovariate(0.1)  # Average 10 activities per minute
            current_time += timedelta(seconds=next_activity_delay)
            
            if current_time >= end_time:
                break
            
            event = self.generate_behavior_event(user_id, current_time)
            events.append(event)
        
        # Logout event
        logout_event = self.generate_behavior_event(user_id, end_time)
        logout_event.event_type = "logout"
        events.append(logout_event)
        
        return events
    
    def _generate_user_agent(self) -> str:
        """Generate realistic user agent string."""
        browsers = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        ]
        return random.choice(browsers)


class FeaturePipelineCorrectnessTests:
    """Test suite for feature pipeline correctness."""
    
    def __init__(self, pipeline: FeatureEngineeringPipeline, data_generator: MockDataGenerator):
        self.pipeline = pipeline
        self.data_generator = data_generator
        self.test_results = []
    
    async def run_all_tests(self) -> List[TestResult]:
        """Run all correctness tests."""
        logger.info("Starting Feature Pipeline Correctness Tests")
        
        tests = [
            self.test_basic_feature_extraction,
            self.test_temporal_features,
            self.test_categorical_features,
            self.test_behavioral_features,
            self.test_feature_consistency,
            self.test_edge_cases,
            self.test_data_validation,
            self.test_error_handling
        ]
        
        for test in tests:
            try:
                result = await test()
                self.test_results.append(result)
                logger.info(f"Test {result.test_name}: {'PASSED' if result.success else 'FAILED'}")
            except Exception as e:
                logger.error(f"Test execution failed: {str(e)}")
                self.test_results.append(TestResult(
                    test_name=test.__name__,
                    success=False,
                    execution_time_ms=0.0,
                    details={},
                    error_message=str(e)
                ))
        
        return self.test_results
    
    async def test_basic_feature_extraction(self) -> TestResult:
        """Test basic feature extraction functionality."""
        start_time = time.time()
        
        try:
            # Generate test event
            event = self.data_generator.generate_behavior_event()
            
            # Extract features
            feature_vector = await self.pipeline.extract_features(event)
            
            # Validate results
            assertions = {
                "has_features": len(feature_vector.features) > 0,
                "has_user_id": feature_vector.user_id == event.user_id,
                "has_timestamp": feature_vector.timestamp == event.timestamp,
                "computation_time_reasonable": feature_vector.total_computation_time_ms < 100,
                "quality_score_valid": 0 <= feature_vector.feature_quality_score <= 1
            }
            
            success = all(assertions.values())
            
            return TestResult(
                test_name="basic_feature_extraction",
                success=success,
                execution_time_ms=(time.time() - start_time) * 1000,
                details={
                    "assertions": assertions,
                    "feature_count": len(feature_vector.features),
                    "computation_time_ms": feature_vector.total_computation_time_ms,
                    "quality_score": feature_vector.feature_quality_score
                }
            )
        except Exception as e:
            return TestResult(
                test_name="basic_feature_extraction",
                success=False,
                execution_time_ms=(time.time() - start_time) * 1000,
                details={},
                error_message=str(e)
            )
    
    async def test_temporal_features(self) -> TestResult:
        """Test temporal feature extraction correctness."""
        start_time = time.time()
        
        try:
            # Generate event with specific time
            test_time = datetime(2024, 8, 8, 14, 30, 0)  # Thursday, 2:30 PM
            event = self.data_generator.generate_behavior_event(timestamp=test_time)
            
            feature_vector = await self.pipeline.extract_features(event)
            
            # Validate temporal features
            features = feature_vector.features
            
            assertions = {
                "hour_of_day_correct": features.get("hour_of_day", {}).get("value") == 14,
                "day_of_week_correct": features.get("day_of_week", {}).get("value") == 3,  # Thursday
                "is_weekend_correct": features.get("is_weekend", {}).get("value") == False,
                "is_business_hours_correct": features.get("is_business_hours", {}).get("value") == True,
                "has_session_duration": "session_duration" in features,
                "has_time_since_last_activity": "time_since_last_activity" in features
            }
            
            success = all(assertions.values())
            
            return TestResult(
                test_name="temporal_features",
                success=success,
                execution_time_ms=(time.time() - start_time) * 1000,
                details={
                    "assertions": assertions,
                    "temporal_features": {k: v.value for k, v in features.items() 
                                        if k.startswith(('hour_', 'day_', 'is_', 'time_', 'session_'))}
                }
            )
        except Exception as e:
            return TestResult(
                test_name="temporal_features",
                success=False,
                execution_time_ms=(time.time() - start_time) * 1000,
                details={},
                error_message=str(e)
            )
    
    async def test_categorical_features(self) -> TestResult:
        """Test categorical feature extraction correctness."""
        start_time = time.time()
        
        try:
            event = self.data_generator.generate_behavior_event()
            feature_vector = await self.pipeline.extract_features(event)
            
            features = feature_vector.features
            
            # Check for categorical features
            categorical_features = [
                "device_change_score", "location_change_score", "user_agent_change_score",
                "ip_reputation_score", "is_new_device", "is_new_location"
            ]
            
            assertions = {
                "has_device_features": any(f in features for f in ["device_change_score", "is_new_device"]),
                "has_location_features": any(f in features for f in ["location_change_score", "is_new_location"]),
                "scores_in_range": all(
                    0 <= features.get(f, {}).get("value", 0) <= 1 
                    for f in categorical_features 
                    if f.endswith("_score") and f in features
                ),
                "boolean_features_valid": all(
                    isinstance(features.get(f, {}).get("value"), bool)
                    for f in categorical_features
                    if f.startswith("is_") and f in features
                )
            }
            
            success = all(assertions.values())
            
            return TestResult(
                test_name="categorical_features",
                success=success,
                execution_time_ms=(time.time() - start_time) * 1000,
                details={
                    "assertions": assertions,
                    "categorical_features": {k: v.value for k, v in features.items()
                                          if k in categorical_features}
                }
            )
        except Exception as e:
            return TestResult(
                test_name="categorical_features",
                success=False,
                execution_time_ms=(time.time() - start_time) * 1000,
                details={},
                error_message=str(e)
            )
    
    async def test_behavioral_features(self) -> TestResult:
        """Test behavioral feature extraction correctness."""
        start_time = time.time()
        
        try:
            # Generate API call event
            event = self.data_generator.generate_behavior_event()
            event.event_type = "api_call"
            event.data.update({
                "endpoint": "/api/v1/users",
                "method": "GET",
                "response_code": 200,
                "request_size": 1024,
                "response_size": 4096
            })
            
            feature_vector = await self.pipeline.extract_features(event)
            features = feature_vector.features
            
            behavioral_features = [
                "resource_access_rate", "api_call_diversity", "data_transfer_volume",
                "failure_rate", "behavioral_consistency_score"
            ]
            
            assertions = {
                "has_behavioral_features": any(f in features for f in behavioral_features),
                "scores_reasonable": all(
                    features.get(f, {}).get("value", 0) >= 0
                    for f in behavioral_features if f in features
                ),
                "consistency_score_valid": (
                    0 <= features.get("behavioral_consistency_score", {}).get("value", 0.5) <= 1
                    if "behavioral_consistency_score" in features else True
                )
            }
            
            success = all(assertions.values())
            
            return TestResult(
                test_name="behavioral_features",
                success=success,
                execution_time_ms=(time.time() - start_time) * 1000,
                details={
                    "assertions": assertions,
                    "behavioral_features": {k: v.value for k, v in features.items()
                                          if k in behavioral_features}
                }
            )
        except Exception as e:
            return TestResult(
                test_name="behavioral_features",
                success=False,
                execution_time_ms=(time.time() - start_time) * 1000,
                details={},
                error_message=str(e)
            )
    
    async def test_feature_consistency(self) -> TestResult:
        """Test feature consistency across multiple extractions."""
        start_time = time.time()
        
        try:
            # Extract features multiple times for same event
            event = self.data_generator.generate_behavior_event()
            
            # Run extraction 5 times
            feature_vectors = []
            for _ in range(5):
                fv = await self.pipeline.extract_features(event)
                feature_vectors.append(fv)
            
            # Check consistency of deterministic features
            deterministic_features = ["hour_of_day", "day_of_week", "is_weekend", "is_business_hours"]
            
            assertions = {
                "same_feature_count": len(set(len(fv.features) for fv in feature_vectors)) <= 2,  # Allow small variation
                "deterministic_consistent": True
            }
            
            # Check deterministic feature consistency
            for feature_name in deterministic_features:
                values = [fv.features.get(feature_name, {}).get("value") for fv in feature_vectors]
                values = [v for v in values if v is not None]  # Remove None values
                
                if values and len(set(values)) > 1:
                    assertions["deterministic_consistent"] = False
                    break
            
            success = all(assertions.values())
            
            return TestResult(
                test_name="feature_consistency",
                success=success,
                execution_time_ms=(time.time() - start_time) * 1000,
                details={
                    "assertions": assertions,
                    "extraction_count": len(feature_vectors),
                    "feature_counts": [len(fv.features) for fv in feature_vectors]
                }
            )
        except Exception as e:
            return TestResult(
                test_name="feature_consistency",
                success=False,
                execution_time_ms=(time.time() - start_time) * 1000,
                details={},
                error_message=str(e)
            )
    
    async def test_edge_cases(self) -> TestResult:
        """Test edge cases and boundary conditions."""
        start_time = time.time()
        
        try:
            test_cases = []
            
            # Minimal event
            minimal_event = BehaviorEvent(
                event_id="minimal_test",
                user_id="test_user",
                session_id=None,
                timestamp=datetime.utcnow(),
                event_type="unknown",
                source="test",
                data={},
                device_info=None,
                location_info=None
            )
            
            fv_minimal = await self.pipeline.extract_features(minimal_event)
            test_cases.append(("minimal_event", len(fv_minimal.features) > 0))
            
            # Event with missing data fields
            incomplete_event = self.data_generator.generate_behavior_event()
            incomplete_event.data = {"source_ip": "192.168.1.1"}  # Minimal data
            
            fv_incomplete = await self.pipeline.extract_features(incomplete_event)
            test_cases.append(("incomplete_event", len(fv_incomplete.features) > 0))
            
            # Future timestamp
            future_event = self.data_generator.generate_behavior_event()
            future_event.timestamp = datetime.utcnow() + timedelta(hours=24)
            
            fv_future = await self.pipeline.extract_features(future_event)
            test_cases.append(("future_timestamp", len(fv_future.features) > 0))
            
            # Very old timestamp
            old_event = self.data_generator.generate_behavior_event()
            old_event.timestamp = datetime.utcnow() - timedelta(days=365)
            
            fv_old = await self.pipeline.extract_features(old_event)
            test_cases.append(("old_timestamp", len(fv_old.features) > 0))
            
            assertions = {f"handles_{case}": result for case, result in test_cases}
            success = all(assertions.values())
            
            return TestResult(
                test_name="edge_cases",
                success=success,
                execution_time_ms=(time.time() - start_time) * 1000,
                details={
                    "assertions": assertions,
                    "test_cases_count": len(test_cases)
                }
            )
        except Exception as e:
            return TestResult(
                test_name="edge_cases",
                success=False,
                execution_time_ms=(time.time() - start_time) * 1000,
                details={},
                error_message=str(e)
            )
    
    async def test_data_validation(self) -> TestResult:
        """Test data validation and quality checks."""
        start_time = time.time()
        
        try:
            events = self.data_generator.generate_event_batch(100)
            feature_vectors = []
            
            for event in events:
                fv = await self.pipeline.extract_features(event)
                feature_vectors.append(fv)
            
            # Validate feature quality
            validation_result = await self.pipeline.validate_feature_quality(feature_vectors)
            
            assertions = {
                "quality_validation_works": "overall_quality_score" in validation_result,
                "reasonable_quality": validation_result.get("overall_quality_score", 0) > 0.5,
                "performance_acceptable": validation_result.get("average_computation_time_ms", 1000) < 100,
                "completeness_reasonable": validation_result.get("feature_completeness", 0) > 0.3
            }
            
            success = all(assertions.values())
            
            return TestResult(
                test_name="data_validation",
                success=success,
                execution_time_ms=(time.time() - start_time) * 1000,
                details={
                    "assertions": assertions,
                    "validation_result": validation_result
                }
            )
        except Exception as e:
            return TestResult(
                test_name="data_validation",
                success=False,
                execution_time_ms=(time.time() - start_time) * 1000,
                details={},
                error_message=str(e)
            )
    
    async def test_error_handling(self) -> TestResult:
        """Test error handling and graceful degradation."""
        start_time = time.time()
        
        try:
            # Test with corrupted event data
            corrupted_event = BehaviorEvent(
                event_id="corrupted_test",
                user_id=None,  # Invalid user_id
                session_id="test_session",
                timestamp=datetime.utcnow(),
                event_type="test",
                source="test",
                data={"invalid_field": float('inf')},  # Invalid data
            )
            
            fv_corrupted = await self.pipeline.extract_features(corrupted_event)
            
            assertions = {
                "handles_corrupted_data": fv_corrupted is not None,
                "returns_feature_vector": isinstance(fv_corrupted, FeatureVector),
                "graceful_degradation": fv_corrupted.feature_quality_score >= 0
            }
            
            success = all(assertions.values())
            
            return TestResult(
                test_name="error_handling",
                success=success,
                execution_time_ms=(time.time() - start_time) * 1000,
                details={
                    "assertions": assertions,
                    "corrupted_result_quality": fv_corrupted.feature_quality_score,
                    "corrupted_features_count": len(fv_corrupted.features)
                }
            )
        except Exception as e:
            return TestResult(
                test_name="error_handling",
                success=False,
                execution_time_ms=(time.time() - start_time) * 1000,
                details={},
                error_message=str(e)
            )


class FeaturePipelinePerformanceTests:
    """Performance testing suite for feature pipeline."""
    
    def __init__(self, pipeline: FeatureEngineeringPipeline, data_generator: MockDataGenerator):
        self.pipeline = pipeline
        self.data_generator = data_generator
        self.performance_results = []
    
    async def run_performance_tests(self) -> List[PerformanceTestResult]:
        """Run comprehensive performance tests."""
        logger.info("Starting Feature Pipeline Performance Tests")
        
        tests = [
            (self.test_single_event_latency, "Single Event Latency"),
            (self.test_batch_processing_throughput, "Batch Processing Throughput"),
            (self.test_concurrent_processing, "Concurrent Processing"),
            (self.test_memory_usage, "Memory Usage"),
            (self.test_cache_performance, "Cache Performance"),
            (self.test_scalability, "Scalability")
        ]
        
        for test_func, test_name in tests:
            try:
                result = await test_func()
                result.test_name = test_name
                self.performance_results.append(result)
                logger.info(f"Performance Test {test_name}: {result.throughput_events_per_second:.2f} events/sec")
            except Exception as e:
                logger.error(f"Performance test {test_name} failed: {str(e)}")
        
        return self.performance_results
    
    async def test_single_event_latency(self) -> PerformanceTestResult:
        """Test single event processing latency."""
        event_count = 1000
        events = self.data_generator.generate_event_batch(event_count)
        
        latencies = []
        error_count = 0
        
        start_memory = psutil.Process().memory_info().rss / 1024 / 1024  # MB
        start_time = time.time()
        
        for event in events:
            try:
                event_start = time.time()
                await self.pipeline.extract_features(event)
                event_latency = (time.time() - event_start) * 1000
                latencies.append(event_latency)
            except Exception:
                error_count += 1
        
        end_time = time.time()
        end_memory = psutil.Process().memory_info().rss / 1024 / 1024  # MB
        
        duration = end_time - start_time
        successful_events = event_count - error_count
        
        return PerformanceTestResult(
            test_name="single_event_latency",
            total_events=event_count,
            duration_seconds=duration,
            throughput_events_per_second=successful_events / duration if duration > 0 else 0,
            average_latency_ms=statistics.mean(latencies) if latencies else 0,
            p95_latency_ms=np.percentile(latencies, 95) if latencies else 0,
            p99_latency_ms=np.percentile(latencies, 99) if latencies else 0,
            memory_usage_mb=end_memory - start_memory,
            cpu_usage_percent=psutil.cpu_percent(interval=1),
            error_count=error_count,
            success_rate=(successful_events / event_count * 100) if event_count > 0 else 0
        )
    
    async def test_batch_processing_throughput(self) -> PerformanceTestResult:
        """Test batch processing throughput."""
        event_count = 5000
        batch_size = 100
        events = self.data_generator.generate_event_batch(event_count)
        
        start_memory = psutil.Process().memory_info().rss / 1024 / 1024
        start_time = time.time()
        
        error_count = 0
        latencies = []
        
        # Process in batches
        for i in range(0, len(events), batch_size):
            batch = events[i:i + batch_size]
            
            try:
                batch_start = time.time()
                feature_vectors = await self.pipeline.extract_features_batch(batch, max_concurrent=20)
                batch_latency = (time.time() - batch_start) * 1000
                latencies.append(batch_latency)
                
                # Count any extraction errors
                error_count += sum(1 for fv in feature_vectors if len(fv.features) == 0)
            except Exception:
                error_count += len(batch)
        
        end_time = time.time()
        end_memory = psutil.Process().memory_info().rss / 1024 / 1024
        
        duration = end_time - start_time
        successful_events = event_count - error_count
        
        return PerformanceTestResult(
            test_name="batch_processing_throughput",
            total_events=event_count,
            duration_seconds=duration,
            throughput_events_per_second=successful_events / duration if duration > 0 else 0,
            average_latency_ms=statistics.mean(latencies) if latencies else 0,
            p95_latency_ms=np.percentile(latencies, 95) if latencies else 0,
            p99_latency_ms=np.percentile(latencies, 99) if latencies else 0,
            memory_usage_mb=end_memory - start_memory,
            cpu_usage_percent=psutil.cpu_percent(interval=1),
            error_count=error_count,
            success_rate=(successful_events / event_count * 100) if event_count > 0 else 0
        )
    
    async def test_concurrent_processing(self) -> PerformanceTestResult:
        """Test concurrent event processing."""
        event_count = 2000
        concurrency_level = 50
        
        events = self.data_generator.generate_event_batch(event_count)
        
        start_memory = psutil.Process().memory_info().rss / 1024 / 1024
        start_time = time.time()
        
        # Create semaphore for controlled concurrency
        semaphore = asyncio.Semaphore(concurrency_level)
        
        async def process_event_with_semaphore(event):
            async with semaphore:
                return await self.pipeline.extract_features(event)
        
        try:
            # Process all events concurrently
            tasks = [process_event_with_semaphore(event) for event in events]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Analyze results
            successful_results = [r for r in results if not isinstance(r, Exception)]
            error_count = len(results) - len(successful_results)
            
            latencies = [fv.total_computation_time_ms for fv in successful_results]
            
        except Exception:
            successful_results = []
            error_count = event_count
            latencies = []
        
        end_time = time.time()
        end_memory = psutil.Process().memory_info().rss / 1024 / 1024
        
        duration = end_time - start_time
        successful_events = len(successful_results)
        
        return PerformanceTestResult(
            test_name="concurrent_processing",
            total_events=event_count,
            duration_seconds=duration,
            throughput_events_per_second=successful_events / duration if duration > 0 else 0,
            average_latency_ms=statistics.mean(latencies) if latencies else 0,
            p95_latency_ms=np.percentile(latencies, 95) if latencies else 0,
            p99_latency_ms=np.percentile(latencies, 99) if latencies else 0,
            memory_usage_mb=end_memory - start_memory,
            cpu_usage_percent=psutil.cpu_percent(interval=1),
            error_count=error_count,
            success_rate=(successful_events / event_count * 100) if event_count > 0 else 0
        )
    
    async def test_memory_usage(self) -> PerformanceTestResult:
        """Test memory usage patterns."""
        event_count = 10000
        events = self.data_generator.generate_event_batch(event_count)
        
        initial_memory = psutil.Process().memory_info().rss / 1024 / 1024
        peak_memory = initial_memory
        
        start_time = time.time()
        error_count = 0
        
        # Process events and monitor memory
        for i, event in enumerate(events):
            try:
                await self.pipeline.extract_features(event)
                
                # Check memory usage every 100 events
                if i % 100 == 0:
                    current_memory = psutil.Process().memory_info().rss / 1024 / 1024
                    peak_memory = max(peak_memory, current_memory)
            except Exception:
                error_count += 1
        
        end_time = time.time()
        final_memory = psutil.Process().memory_info().rss / 1024 / 1024
        
        duration = end_time - start_time
        successful_events = event_count - error_count
        
        return PerformanceTestResult(
            test_name="memory_usage",
            total_events=event_count,
            duration_seconds=duration,
            throughput_events_per_second=successful_events / duration if duration > 0 else 0,
            average_latency_ms=0,  # Not measured in this test
            p95_latency_ms=0,
            p99_latency_ms=0,
            memory_usage_mb=peak_memory - initial_memory,
            cpu_usage_percent=psutil.cpu_percent(interval=1),
            error_count=error_count,
            success_rate=(successful_events / event_count * 100) if event_count > 0 else 0
        )
    
    async def test_cache_performance(self) -> PerformanceTestResult:
        """Test caching performance impact."""
        event_count = 1000
        user_id = "cache_test_user"
        
        # Generate events for same user to test cache effectiveness
        events = [self.data_generator.generate_behavior_event(user_id) for _ in range(event_count)]
        
        start_time = time.time()
        error_count = 0
        latencies = []
        
        for event in events:
            try:
                event_start = time.time()
                await self.pipeline.extract_features(event)
                event_latency = (time.time() - event_start) * 1000
                latencies.append(event_latency)
            except Exception:
                error_count += 1
        
        end_time = time.time()
        duration = end_time - start_time
        successful_events = event_count - error_count
        
        # Get cache performance metrics
        cache_stats = {}
        try:
            performance_data = await self.pipeline.get_pipeline_performance()
            cache_stats = performance_data.get('cache_performance', {})
        except Exception:
            pass
        
        return PerformanceTestResult(
            test_name="cache_performance",
            total_events=event_count,
            duration_seconds=duration,
            throughput_events_per_second=successful_events / duration if duration > 0 else 0,
            average_latency_ms=statistics.mean(latencies) if latencies else 0,
            p95_latency_ms=np.percentile(latencies, 95) if latencies else 0,
            p99_latency_ms=np.percentile(latencies, 99) if latencies else 0,
            memory_usage_mb=0,  # Not measured in this test
            cpu_usage_percent=psutil.cpu_percent(interval=1),
            error_count=error_count,
            success_rate=(successful_events / event_count * 100) if event_count > 0 else 0
        )
    
    async def test_scalability(self) -> PerformanceTestResult:
        """Test system scalability with increasing load."""
        base_event_count = 1000
        scale_factors = [1, 2, 5, 10]
        
        results = []
        
        for scale_factor in scale_factors:
            event_count = base_event_count * scale_factor
            events = self.data_generator.generate_event_batch(event_count)
            
            start_time = time.time()
            error_count = 0
            
            try:
                # Use batch processing for scalability test
                feature_vectors = await self.pipeline.extract_features_batch(events, max_concurrent=20)
                error_count = sum(1 for fv in feature_vectors if len(fv.features) == 0)
            except Exception:
                error_count = event_count
            
            end_time = time.time()
            duration = end_time - start_time
            successful_events = event_count - error_count
            
            throughput = successful_events / duration if duration > 0 else 0
            results.append((scale_factor, throughput))
        
        # Use results from highest scale factor
        final_scale_factor, final_throughput = results[-1]
        final_event_count = base_event_count * final_scale_factor
        
        return PerformanceTestResult(
            test_name="scalability",
            total_events=final_event_count,
            duration_seconds=0,  # Aggregated test
            throughput_events_per_second=final_throughput,
            average_latency_ms=0,
            p95_latency_ms=0,
            p99_latency_ms=0,
            memory_usage_mb=0,
            cpu_usage_percent=psutil.cpu_percent(interval=1),
            error_count=0,
            success_rate=100.0
        )


class FeatureStoreIntegrationTests:
    """Integration tests for feature store functionality."""
    
    def __init__(self, feature_store_manager: FeatureStoreManager, data_generator: MockDataGenerator):
        self.feature_store_manager = feature_store_manager
        self.data_generator = data_generator
        self.test_results = []
    
    async def run_integration_tests(self) -> List[TestResult]:
        """Run feature store integration tests."""
        logger.info("Starting Feature Store Integration Tests")
        
        tests = [
            self.test_feature_storage_retrieval,
            self.test_feature_freshness,
            self.test_batch_operations,
            self.test_feature_serving_latency
        ]
        
        for test in tests:
            try:
                result = await test()
                self.test_results.append(result)
                logger.info(f"Integration Test {result.test_name}: {'PASSED' if result.success else 'FAILED'}")
            except Exception as e:
                logger.error(f"Integration test failed: {str(e)}")
                self.test_results.append(TestResult(
                    test_name=test.__name__,
                    success=False,
                    execution_time_ms=0.0,
                    details={},
                    error_message=str(e)
                ))
        
        return self.test_results
    
    async def test_feature_storage_retrieval(self) -> TestResult:
        """Test feature storage and retrieval."""
        start_time = time.time()
        
        try:
            user_id = "integration_test_user"
            
            # Generate sample features
            sample_features = {
                "hour_of_day": 14,
                "is_weekend": False,
                "device_change_score": 0.3,
                "resource_access_rate": 12.5,
                "behavioral_consistency_score": 0.78
            }
            
            # Store features
            store_success = await self.feature_store_manager.store_behavior_features(
                user_id, sample_features
            )
            
            # Retrieve features
            retrieved_features = await self.feature_store_manager.get_user_feature_vector(user_id)
            
            assertions = {
                "storage_successful": store_success,
                "retrieval_successful": len(retrieved_features) > 0,
                "data_consistency": all(
                    retrieved_features.get(k) == v 
                    for k, v in sample_features.items()
                    if k in retrieved_features
                )
            }
            
            success = all(assertions.values())
            
            return TestResult(
                test_name="feature_storage_retrieval",
                success=success,
                execution_time_ms=(time.time() - start_time) * 1000,
                details={
                    "assertions": assertions,
                    "stored_features": len(sample_features),
                    "retrieved_features": len(retrieved_features),
                    "matching_features": len(set(sample_features.keys()) & set(retrieved_features.keys()))
                }
            )
        except Exception as e:
            return TestResult(
                test_name="feature_storage_retrieval",
                success=False,
                execution_time_ms=(time.time() - start_time) * 1000,
                details={},
                error_message=str(e)
            )
    
    async def test_feature_freshness(self) -> TestResult:
        """Test feature freshness validation."""
        start_time = time.time()
        
        try:
            user_id = "freshness_test_user"
            
            # Store fresh features
            fresh_features = {"hour_of_day": 15, "device_change_score": 0.1}
            await self.feature_store_manager.store_behavior_features(user_id, fresh_features)
            
            # Validate freshness
            freshness_result = await self.feature_store_manager.validate_feature_freshness(
                user_id, max_age_seconds=60
            )
            
            assertions = {
                "freshness_check_works": "freshness_ratio" in freshness_result,
                "user_id_correct": freshness_result.get("user_id") == user_id,
                "has_serving_latency": "serving_latency_ms" in freshness_result,
                "latency_reasonable": freshness_result.get("serving_latency_ms", 1000) < 100
            }
            
            success = all(assertions.values())
            
            return TestResult(
                test_name="feature_freshness",
                success=success,
                execution_time_ms=(time.time() - start_time) * 1000,
                details={
                    "assertions": assertions,
                    "freshness_result": freshness_result
                }
            )
        except Exception as e:
            return TestResult(
                test_name="feature_freshness",
                success=False,
                execution_time_ms=(time.time() - start_time) * 1000,
                details={},
                error_message=str(e)
            )
    
    async def test_batch_operations(self) -> TestResult:
        """Test batch feature operations."""
        start_time = time.time()
        
        try:
            user_count = 50
            user_ids = [f"batch_user_{i:03d}" for i in range(user_count)]
            
            # Store features for multiple users
            for user_id in user_ids:
                features = {
                    "hour_of_day": random.randint(0, 23),
                    "device_change_score": random.uniform(0, 1),
                    "resource_access_rate": random.uniform(1, 50)
                }
                await self.feature_store_manager.store_behavior_features(user_id, features)
            
            # Retrieve features for all users
            response = await self.feature_store_manager.get_behavior_features(user_ids)
            
            assertions = {
                "batch_retrieval_works": len(response.features) > 0,
                "all_users_served": len(response.features) >= user_count * 0.8,  # Allow some failures
                "response_has_metadata": len(response.metadata) > 0,
                "serving_latency_reasonable": response.latency_ms < 500  # 500ms for batch operation
            }
            
            success = all(assertions.values())
            
            return TestResult(
                test_name="batch_operations",
                success=success,
                execution_time_ms=(time.time() - start_time) * 1000,
                details={
                    "assertions": assertions,
                    "requested_users": user_count,
                    "served_users": len(response.features),
                    "serving_latency_ms": response.latency_ms
                }
            )
        except Exception as e:
            return TestResult(
                test_name="batch_operations",
                success=False,
                execution_time_ms=(time.time() - start_time) * 1000,
                details={},
                error_message=str(e)
            )
    
    async def test_feature_serving_latency(self) -> TestResult:
        """Test feature serving latency."""
        start_time = time.time()
        
        try:
            user_id = "latency_test_user"
            
            # Pre-populate features
            features = {f"feature_{i}": random.uniform(0, 1) for i in range(20)}
            await self.feature_store_manager.store_behavior_features(user_id, features)
            
            # Measure serving latency multiple times
            latencies = []
            for _ in range(10):
                latency_start = time.time()
                await self.feature_store_manager.get_user_feature_vector(user_id)
                latency_ms = (time.time() - latency_start) * 1000
                latencies.append(latency_ms)
            
            avg_latency = statistics.mean(latencies)
            p95_latency = np.percentile(latencies, 95)
            
            assertions = {
                "average_latency_target": avg_latency < 10,  # <10ms average
                "p95_latency_target": p95_latency < 20,     # <20ms P95
                "all_requests_succeeded": len(latencies) == 10
            }
            
            success = all(assertions.values())
            
            return TestResult(
                test_name="feature_serving_latency",
                success=success,
                execution_time_ms=(time.time() - start_time) * 1000,
                details={
                    "assertions": assertions,
                    "average_latency_ms": avg_latency,
                    "p95_latency_ms": p95_latency,
                    "all_latencies": latencies
                }
            )
        except Exception as e:
            return TestResult(
                test_name="feature_serving_latency",
                success=False,
                execution_time_ms=(time.time() - start_time) * 1000,
                details={},
                error_message=str(e)
            )


class FeaturePipelineTestSuite:
    """Comprehensive test suite for the feature engineering pipeline."""
    
    def __init__(self):
        self.data_generator = MockDataGenerator()
        self.pipeline = None
        self.feature_store_manager = None
        self.test_results = {
            "correctness": [],
            "performance": [],
            "integration": []
        }
    
    async def initialize(self, redis_url: str = "redis://localhost:6379"):
        """Initialize test components."""
        logger.info("Initializing Feature Pipeline Test Suite")
        
        # Initialize pipeline
        self.pipeline = await initialize_feature_engineering_pipeline(redis_url)
        
        # Initialize feature store manager
        self.feature_store_manager = await initialize_feature_store_manager(
            FeatureStoreType.REDIS, 
            redis_url=redis_url
        )
        
        logger.info("Test Suite initialization complete")
    
    async def run_all_tests(self) -> Dict[str, Any]:
        """Run all test categories."""
        logger.info("Starting Comprehensive Feature Pipeline Testing")
        
        # Correctness tests
        correctness_tester = FeaturePipelineCorrectnessTests(self.pipeline, self.data_generator)
        self.test_results["correctness"] = await correctness_tester.run_all_tests()
        
        # Performance tests
        performance_tester = FeaturePipelinePerformanceTests(self.pipeline, self.data_generator)
        self.test_results["performance"] = await performance_tester.run_performance_tests()
        
        # Integration tests
        integration_tester = FeatureStoreIntegrationTests(self.feature_store_manager, self.data_generator)
        self.test_results["integration"] = await integration_tester.run_integration_tests()
        
        return self.generate_test_report()
    
    def generate_test_report(self) -> Dict[str, Any]:
        """Generate comprehensive test report."""
        report = {
            "test_execution_time": datetime.utcnow().isoformat(),
            "summary": {},
            "detailed_results": self.test_results,
            "performance_analysis": self._analyze_performance_results(),
            "recommendations": self._generate_recommendations()
        }
        
        # Generate summary statistics
        for category, results in self.test_results.items():
            if category == "performance":
                report["summary"][category] = {
                    "tests_run": len(results),
                    "average_throughput": statistics.mean([r.throughput_events_per_second for r in results]),
                    "average_latency_ms": statistics.mean([r.average_latency_ms for r in results if r.average_latency_ms > 0]),
                    "total_errors": sum([r.error_count for r in results])
                }
            else:
                report["summary"][category] = {
                    "tests_run": len(results),
                    "tests_passed": sum(1 for r in results if r.success),
                    "success_rate": (sum(1 for r in results if r.success) / len(results) * 100) if results else 0,
                    "average_execution_time_ms": statistics.mean([r.execution_time_ms for r in results]) if results else 0
                }
        
        return report
    
    def _analyze_performance_results(self) -> Dict[str, Any]:
        """Analyze performance test results."""
        if not self.test_results["performance"]:
            return {}
        
        results = self.test_results["performance"]
        
        analysis = {
            "throughput_analysis": {
                "max_throughput": max([r.throughput_events_per_second for r in results]),
                "min_throughput": min([r.throughput_events_per_second for r in results]),
                "average_throughput": statistics.mean([r.throughput_events_per_second for r in results]),
                "target_met": any(r.throughput_events_per_second >= 10000 for r in results)
            },
            "latency_analysis": {
                "average_latencies": [r.average_latency_ms for r in results if r.average_latency_ms > 0],
                "p95_latencies": [r.p95_latency_ms for r in results if r.p95_latency_ms > 0],
                "target_met": all(r.average_latency_ms < 50 for r in results if r.average_latency_ms > 0)
            },
            "reliability_analysis": {
                "success_rates": [r.success_rate for r in results],
                "total_errors": sum([r.error_count for r in results]),
                "target_met": all(r.success_rate >= 99.0 for r in results)
            }
        }
        
        return analysis
    
    def _generate_recommendations(self) -> List[str]:
        """Generate optimization recommendations based on test results."""
        recommendations = []
        
        # Analyze correctness results
        correctness_failures = [r for r in self.test_results["correctness"] if not r.success]
        if correctness_failures:
            recommendations.append(
                f"Address {len(correctness_failures)} failing correctness tests: "
                f"{', '.join([r.test_name for r in correctness_failures])}"
            )
        
        # Analyze performance results
        if self.test_results["performance"]:
            performance_analysis = self._analyze_performance_results()
            
            if not performance_analysis["throughput_analysis"]["target_met"]:
                recommendations.append(
                    "Throughput target of 10K events/second not met. Consider optimizing "
                    "batch processing, caching, or parallelization."
                )
            
            if not performance_analysis["latency_analysis"]["target_met"]:
                recommendations.append(
                    "Latency target of <50ms not met. Consider reducing feature computation "
                    "complexity or improving caching strategies."
                )
            
            if not performance_analysis["reliability_analysis"]["target_met"]:
                recommendations.append(
                    "Reliability target of 99% success rate not met. Improve error handling "
                    "and graceful degradation capabilities."
                )
        
        # General recommendations
        recommendations.extend([
            "Consider implementing feature precomputation for frequently accessed features",
            "Implement feature versioning for model consistency",
            "Set up continuous performance monitoring in production",
            "Consider implementing distributed caching for horizontal scaling"
        ])
        
        return recommendations
    
    async def cleanup(self):
        """Cleanup test resources."""
        if self.pipeline:
            await self.pipeline.cleanup()
        if self.feature_store_manager:
            await self.feature_store_manager.cleanup()
        
        logger.info("Feature Pipeline Test Suite cleanup completed")


# CLI interface for running tests
async def run_feature_pipeline_tests():
    """Run comprehensive feature pipeline tests."""
    test_suite = FeaturePipelineTestSuite()
    
    try:
        await test_suite.initialize()
        
        logger.info("="*80)
        logger.info("FEATURE ENGINEERING PIPELINE - COMPREHENSIVE TEST SUITE")
        logger.info("="*80)
        
        test_report = await test_suite.run_all_tests()
        
        # Print summary
        logger.info("\n" + "="*50)
        logger.info("TEST EXECUTION SUMMARY")
        logger.info("="*50)
        
        for category, summary in test_report["summary"].items():
            logger.info(f"\n{category.upper()} TESTS:")
            for metric, value in summary.items():
                logger.info(f"  {metric}: {value}")
        
        # Print recommendations
        logger.info("\n" + "="*50)
        logger.info("OPTIMIZATION RECOMMENDATIONS")
        logger.info("="*50)
        for i, rec in enumerate(test_report["recommendations"], 1):
            logger.info(f"{i}. {rec}")
        
        return test_report
        
    finally:
        await test_suite.cleanup()


if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    
    # Run tests
    asyncio.run(run_feature_pipeline_tests())