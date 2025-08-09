"""
A/B Testing Framework for AI/ML Models

Comprehensive A/B testing system for comparing model versions, 
performance optimization, and gradual rollout strategies.
"""

import asyncio
import logging
import random
import hashlib
import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable, Union, Tuple
from enum import Enum
from collections import defaultdict
import numpy as np
import pandas as pd
from scipy import stats
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

logger = logging.getLogger(__name__)


class ABTestStatus(Enum):
    """A/B test status."""
    DRAFT = "draft"
    RUNNING = "running"
    COMPLETED = "completed"
    STOPPED = "stopped"
    FAILED = "failed"


class TrafficSplitStrategy(Enum):
    """Traffic splitting strategies."""
    RANDOM = "random"
    USER_HASH = "user_hash"
    GEOLOCATION = "geolocation"
    GRADUAL_ROLLOUT = "gradual_rollout"
    PERFORMANCE_BASED = "performance_based"


class StatisticalTest(Enum):
    """Statistical tests for significance."""
    T_TEST = "t_test"
    CHI_SQUARE = "chi_square"
    MANN_WHITNEY_U = "mann_whitney_u"
    BAYESIAN = "bayesian"


@dataclass
class ModelVariant:
    """Model variant configuration for A/B testing."""
    variant_id: str
    model_id: str
    model_version: str
    traffic_percentage: float
    
    # Model instance
    model: Optional[Any] = None
    
    # Performance tracking
    request_count: int = 0
    inference_times: List[float] = field(default_factory=list)
    predictions: List[Any] = field(default_factory=list)
    ground_truth: List[Any] = field(default_factory=list)
    
    # Metrics
    accuracy: float = 0.0
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0
    avg_inference_time: float = 0.0
    
    # Configuration
    enabled: bool = True
    created_at: datetime = field(default_factory=datetime.utcnow)
    
    def add_result(self, prediction: Any, ground_truth: Optional[Any] = None, inference_time: float = 0.0):
        """Add prediction result to variant."""
        self.request_count += 1
        self.predictions.append(prediction)
        self.inference_times.append(inference_time)
        
        if ground_truth is not None:
            self.ground_truth.append(ground_truth)
    
    def calculate_metrics(self):
        """Calculate performance metrics."""
        if self.inference_times:
            self.avg_inference_time = np.mean(self.inference_times)
        
        if len(self.ground_truth) > 0 and len(self.predictions) >= len(self.ground_truth):
            y_true = self.ground_truth
            y_pred = self.predictions[:len(y_true)]
            
            try:
                self.accuracy = accuracy_score(y_true, y_pred)
                self.precision = precision_score(y_true, y_pred, average='weighted', zero_division=0)
                self.recall = recall_score(y_true, y_pred, average='weighted', zero_division=0)
                self.f1_score = f1_score(y_true, y_pred, average='weighted', zero_division=0)
            except Exception as e:
                logger.warning(f"Failed to calculate metrics for variant {self.variant_id}: {e}")


@dataclass
class ABTestConfig:
    """A/B test configuration."""
    test_id: str
    test_name: str
    variants: List[ModelVariant]
    
    # Traffic configuration
    traffic_split_strategy: TrafficSplitStrategy = TrafficSplitStrategy.RANDOM
    total_traffic_percentage: float = 100.0  # Percentage of total traffic to include in test
    
    # Test duration
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    max_duration_hours: int = 168  # 1 week default
    
    # Statistical configuration
    statistical_test: StatisticalTest = StatisticalTest.T_TEST
    significance_level: float = 0.05
    minimum_sample_size: int = 1000
    minimum_effect_size: float = 0.05  # Minimum practical difference
    
    # Success metrics
    primary_metric: str = "accuracy"
    secondary_metrics: List[str] = field(default_factory=lambda: ["precision", "recall", "inference_time"])
    
    # Early stopping
    enable_early_stopping: bool = True
    early_stopping_threshold: float = 0.01  # Stop if p-value < threshold
    
    # Monitoring
    update_interval_minutes: int = 15
    alert_thresholds: Dict[str, float] = field(default_factory=dict)


@dataclass
class ABTestResult:
    """A/B test results."""
    test_id: str
    status: ABTestStatus
    start_time: datetime
    end_time: Optional[datetime] = None
    
    # Variant results
    variant_results: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    
    # Statistical analysis
    statistical_significance: Dict[str, float] = field(default_factory=dict)
    p_values: Dict[str, float] = field(default_factory=dict)
    confidence_intervals: Dict[str, Tuple[float, float]] = field(default_factory=dict)
    
    # Winner determination
    winning_variant: Optional[str] = None
    improvement_percentage: float = 0.0
    
    # Recommendations
    recommendation: str = ""
    risk_assessment: str = ""
    rollout_strategy: str = ""


class ABTestingFramework:
    """
    Comprehensive A/B testing framework for AI/ML models with
    statistical significance testing and gradual rollout capabilities.
    """
    
    def __init__(self):
        self._active_tests: Dict[str, ABTestConfig] = {}
        self._test_results: Dict[str, ABTestResult] = {}
        self._traffic_router = TrafficRouter()
        self._monitoring_tasks: Dict[str, asyncio.Task] = {}
        
        logger.info("A/B Testing Framework initialized")
    
    async def create_test(self, config: ABTestConfig) -> str:
        """Create a new A/B test."""
        # Validate configuration
        self._validate_test_config(config)
        
        # Initialize variants
        total_traffic = sum(variant.traffic_percentage for variant in config.variants)
        if abs(total_traffic - 100.0) > 0.001:
            raise ValueError(f"Variant traffic percentages must sum to 100%, got {total_traffic}%")
        
        # Create test result tracking
        result = ABTestResult(
            test_id=config.test_id,
            status=ABTestStatus.DRAFT,
            start_time=config.start_time or datetime.utcnow()
        )
        
        self._test_results[config.test_id] = result
        self._active_tests[config.test_id] = config
        
        logger.info(f"A/B test created: {config.test_id}")
        return config.test_id
    
    async def start_test(self, test_id: str) -> bool:
        """Start an A/B test."""
        if test_id not in self._active_tests:
            raise ValueError(f"Test {test_id} not found")
        
        config = self._active_tests[test_id]
        result = self._test_results[test_id]
        
        # Update status
        result.status = ABTestStatus.RUNNING
        result.start_time = datetime.utcnow()
        
        # Set end time if not specified
        if not config.end_time:
            config.end_time = result.start_time + timedelta(hours=config.max_duration_hours)
        
        # Start monitoring task
        self._monitoring_tasks[test_id] = asyncio.create_task(
            self._monitor_test(test_id)
        )
        
        logger.info(f"A/B test started: {test_id}")
        return True
    
    async def stop_test(self, test_id: str) -> ABTestResult:
        """Stop an A/B test and return results."""
        if test_id not in self._active_tests:
            raise ValueError(f"Test {test_id} not found")
        
        # Stop monitoring
        if test_id in self._monitoring_tasks:
            self._monitoring_tasks[test_id].cancel()
            del self._monitoring_tasks[test_id]
        
        # Update status
        result = self._test_results[test_id]
        result.status = ABTestStatus.COMPLETED
        result.end_time = datetime.utcnow()
        
        # Perform final analysis
        await self._analyze_test_results(test_id)
        
        logger.info(f"A/B test stopped: {test_id}")
        return result
    
    async def route_request(self, test_id: str, user_id: str, request_data: Dict[str, Any]) -> str:
        """Route request to appropriate model variant."""
        if test_id not in self._active_tests:
            raise ValueError(f"Test {test_id} not found")
        
        config = self._active_tests[test_id]
        result = self._test_results[test_id]
        
        if result.status != ABTestStatus.RUNNING:
            # Default to first variant if test not running
            return config.variants[0].variant_id
        
        # Determine if request should be included in test
        if not self._should_include_in_test(config, user_id, request_data):
            return config.variants[0].variant_id  # Control variant
        
        # Route to variant based on strategy
        variant_id = self._traffic_router.route_traffic(config, user_id, request_data)
        
        return variant_id
    
    async def record_prediction(
        self,
        test_id: str,
        variant_id: str,
        prediction: Any,
        ground_truth: Optional[Any] = None,
        inference_time: float = 0.0
    ):
        """Record prediction result for a variant."""
        if test_id not in self._active_tests:
            return
        
        config = self._active_tests[test_id]
        
        # Find variant and record result
        for variant in config.variants:
            if variant.variant_id == variant_id:
                variant.add_result(prediction, ground_truth, inference_time)
                variant.calculate_metrics()
                break
    
    async def get_test_status(self, test_id: str) -> Dict[str, Any]:
        """Get current test status and metrics."""
        if test_id not in self._active_tests:
            raise ValueError(f"Test {test_id} not found")
        
        config = self._active_tests[test_id]
        result = self._test_results[test_id]
        
        # Collect variant metrics
        variant_metrics = {}
        for variant in config.variants:
            variant_metrics[variant.variant_id] = {
                'request_count': variant.request_count,
                'accuracy': variant.accuracy,
                'precision': variant.precision,
                'recall': variant.recall,
                'f1_score': variant.f1_score,
                'avg_inference_time': variant.avg_inference_time,
                'traffic_percentage': variant.traffic_percentage
            }
        
        return {
            'test_id': test_id,
            'status': result.status.value,
            'start_time': result.start_time,
            'end_time': result.end_time,
            'variants': variant_metrics,
            'statistical_significance': result.statistical_significance,
            'winning_variant': result.winning_variant,
            'improvement_percentage': result.improvement_percentage
        }
    
    def _validate_test_config(self, config: ABTestConfig):
        """Validate A/B test configuration."""
        if len(config.variants) < 2:
            raise ValueError("A/B test requires at least 2 variants")
        
        if not all(variant.model for variant in config.variants):
            raise ValueError("All variants must have a model assigned")
        
        if config.significance_level <= 0 or config.significance_level >= 1:
            raise ValueError("Significance level must be between 0 and 1")
        
        if config.minimum_sample_size < 100:
            raise ValueError("Minimum sample size must be at least 100")
    
    def _should_include_in_test(self, config: ABTestConfig, user_id: str, request_data: Dict[str, Any]) -> bool:
        """Determine if request should be included in A/B test."""
        # Check traffic percentage
        if config.total_traffic_percentage < 100.0:
            user_hash = int(hashlib.md5(user_id.encode()).hexdigest(), 16) % 100
            if user_hash >= config.total_traffic_percentage:
                return False
        
        # Additional filtering logic can be added here
        return True
    
    async def _monitor_test(self, test_id: str):
        """Monitor A/B test progress."""
        config = self._active_tests[test_id]
        
        while True:
            try:
                # Check if test should end
                if datetime.utcnow() >= config.end_time:
                    await self.stop_test(test_id)
                    break
                
                # Perform periodic analysis
                await self._analyze_test_results(test_id)
                
                # Check for early stopping
                if config.enable_early_stopping:
                    should_stop = await self._check_early_stopping(test_id)
                    if should_stop:
                        await self.stop_test(test_id)
                        break
                
                # Wait for next update
                await asyncio.sleep(config.update_interval_minutes * 60)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Monitoring error for test {test_id}: {e}")
                await asyncio.sleep(60)  # Wait before retrying
    
    async def _analyze_test_results(self, test_id: str):
        """Perform statistical analysis of test results."""
        config = self._active_tests[test_id]
        result = self._test_results[test_id]
        
        # Check if we have enough data
        total_samples = sum(variant.request_count for variant in config.variants)
        if total_samples < config.minimum_sample_size:
            return
        
        # Perform statistical tests
        control_variant = config.variants[0]  # Assume first variant is control
        
        for i, test_variant in enumerate(config.variants[1:], 1):
            if len(control_variant.ground_truth) < 100 or len(test_variant.ground_truth) < 100:
                continue
            
            # Compare primary metric
            p_value = self._perform_statistical_test(
                control_variant, test_variant, config.primary_metric, config.statistical_test
            )
            
            result.p_values[f"variant_{i}"] = p_value
            result.statistical_significance[f"variant_{i}"] = p_value < config.significance_level
            
            # Calculate improvement
            control_metric = getattr(control_variant, config.primary_metric, 0)
            test_metric = getattr(test_variant, config.primary_metric, 0)
            
            if control_metric > 0:
                improvement = ((test_metric - control_metric) / control_metric) * 100
                if improvement > result.improvement_percentage and p_value < config.significance_level:
                    result.winning_variant = test_variant.variant_id
                    result.improvement_percentage = improvement
        
        # Generate recommendations
        result.recommendation = self._generate_recommendation(config, result)
    
    def _perform_statistical_test(
        self,
        control_variant: ModelVariant,
        test_variant: ModelVariant,
        metric: str,
        test_type: StatisticalTest
    ) -> float:
        """Perform statistical significance test."""
        control_values = self._extract_metric_values(control_variant, metric)
        test_values = self._extract_metric_values(test_variant, metric)
        
        if len(control_values) == 0 or len(test_values) == 0:
            return 1.0  # No significance
        
        try:
            if test_type == StatisticalTest.T_TEST:
                statistic, p_value = stats.ttest_ind(control_values, test_values)
            elif test_type == StatisticalTest.MANN_WHITNEY_U:
                statistic, p_value = stats.mannwhitneyu(control_values, test_values, alternative='two-sided')
            elif test_type == StatisticalTest.CHI_SQUARE:
                # For categorical outcomes
                control_counts = np.bincount(control_values)
                test_counts = np.bincount(test_values)
                
                # Pad to same length
                max_len = max(len(control_counts), len(test_counts))
                control_counts = np.pad(control_counts, (0, max_len - len(control_counts)))
                test_counts = np.pad(test_counts, (0, max_len - len(test_counts)))
                
                chi2, p_value = stats.chi2_contingency([control_counts, test_counts])[:2]
            else:
                # Default to t-test
                statistic, p_value = stats.ttest_ind(control_values, test_values)
            
            return p_value
        
        except Exception as e:
            logger.error(f"Statistical test failed: {e}")
            return 1.0
    
    def _extract_metric_values(self, variant: ModelVariant, metric: str) -> List[float]:
        """Extract metric values for statistical testing."""
        if metric == "accuracy" and variant.ground_truth:
            # Calculate per-sample accuracy
            y_true = variant.ground_truth
            y_pred = variant.predictions[:len(y_true)]
            return [1.0 if pred == true else 0.0 for pred, true in zip(y_pred, y_true)]
        elif metric == "inference_time":
            return variant.inference_times
        else:
            # For other metrics, use repeated value (not ideal but functional)
            metric_value = getattr(variant, metric, 0.0)
            return [metric_value] * variant.request_count
    
    async def _check_early_stopping(self, test_id: str) -> bool:
        """Check if test should be stopped early."""
        config = self._active_tests[test_id]
        result = self._test_results[test_id]
        
        # Check if any variant has strong statistical significance
        for variant_key, p_value in result.p_values.items():
            if p_value < config.early_stopping_threshold:
                logger.info(f"Early stopping triggered for test {test_id}: p-value {p_value}")
                return True
        
        return False
    
    def _generate_recommendation(self, config: ABTestConfig, result: ABTestResult) -> str:
        """Generate recommendation based on test results."""
        if result.winning_variant:
            improvement = result.improvement_percentage
            variant_id = result.winning_variant
            
            if improvement > 10.0:
                return f"Strong recommendation: Roll out variant {variant_id} (improvement: {improvement:.1f}%)"
            elif improvement > 5.0:
                return f"Moderate recommendation: Consider rolling out variant {variant_id} (improvement: {improvement:.1f}%)"
            else:
                return f"Weak signal: Variant {variant_id} shows improvement ({improvement:.1f}%) but may not be practically significant"
        else:
            return "No statistically significant winner detected. Continue monitoring or extend test duration."


class TrafficRouter:
    """Handles traffic routing for A/B tests."""
    
    def route_traffic(self, config: ABTestConfig, user_id: str, request_data: Dict[str, Any]) -> str:
        """Route traffic based on configured strategy."""
        if config.traffic_split_strategy == TrafficSplitStrategy.RANDOM:
            return self._random_routing(config.variants)
        elif config.traffic_split_strategy == TrafficSplitStrategy.USER_HASH:
            return self._hash_based_routing(config.variants, user_id)
        elif config.traffic_split_strategy == TrafficSplitStrategy.GRADUAL_ROLLOUT:
            return self._gradual_rollout_routing(config.variants, config.start_time)
        else:
            return self._random_routing(config.variants)
    
    def _random_routing(self, variants: List[ModelVariant]) -> str:
        """Random traffic routing."""
        rand_val = random.random() * 100
        cumulative_percentage = 0
        
        for variant in variants:
            cumulative_percentage += variant.traffic_percentage
            if rand_val <= cumulative_percentage:
                return variant.variant_id
        
        return variants[-1].variant_id  # Fallback
    
    def _hash_based_routing(self, variants: List[ModelVariant], user_id: str) -> str:
        """Consistent hash-based routing."""
        user_hash = int(hashlib.md5(user_id.encode()).hexdigest(), 16) % 100
        cumulative_percentage = 0
        
        for variant in variants:
            cumulative_percentage += variant.traffic_percentage
            if user_hash < cumulative_percentage:
                return variant.variant_id
        
        return variants[-1].variant_id  # Fallback
    
    def _gradual_rollout_routing(self, variants: List[ModelVariant], start_time: datetime) -> str:
        """Gradual rollout routing - increase test variant traffic over time."""
        if len(variants) != 2:
            return self._random_routing(variants)  # Fallback for non-binary tests
        
        # Calculate time-based traffic split
        hours_since_start = (datetime.utcnow() - start_time).total_seconds() / 3600
        rollout_hours = 72  # 3 days for full rollout
        
        # Gradually increase test variant from 10% to 50%
        test_percentage = min(10 + (40 * hours_since_start / rollout_hours), 50)
        control_percentage = 100 - test_percentage
        
        # Update variant percentages
        variants[0].traffic_percentage = control_percentage
        variants[1].traffic_percentage = test_percentage
        
        return self._random_routing(variants)


# Export for external use
__all__ = [
    'ABTestingFramework',
    'ModelVariant',
    'ABTestResult',
    'ABTestConfig',
    'ABTestStatus',
    'TrafficSplitStrategy',
    'StatisticalTest'
]