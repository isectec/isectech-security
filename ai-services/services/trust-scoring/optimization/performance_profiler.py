"""
Trust Scoring Performance Profiler

Comprehensive performance profiling and optimization analysis for
trust scoring engines with bottleneck identification and recommendations.
"""

import asyncio
import logging
import time
import threading
import cProfile
import pstats
import io
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable, Union
from collections import defaultdict, deque
import psutil
import numpy as np
import pandas as pd
from concurrent.futures import ThreadPoolExecutor
import resource
import traceback
import sys

logger = logging.getLogger(__name__)


@dataclass
class PerformanceMetrics:
    """Comprehensive performance metrics."""
    timestamp: datetime = field(default_factory=datetime.utcnow)
    
    # Timing metrics
    execution_time_ms: float = 0.0
    cpu_time_ms: float = 0.0
    wall_time_ms: float = 0.0
    
    # Resource usage
    memory_usage_mb: float = 0.0
    memory_peak_mb: float = 0.0
    cpu_usage_percent: float = 0.0
    
    # Function-level metrics
    function_calls: Dict[str, int] = field(default_factory=dict)
    function_times: Dict[str, float] = field(default_factory=dict)
    
    # Trust scoring specific
    trust_calculations_per_second: float = 0.0
    cache_hit_rate: float = 0.0
    database_query_time_ms: float = 0.0
    external_service_time_ms: float = 0.0
    
    # Threading metrics
    active_threads: int = 0
    thread_contention_ms: float = 0.0
    
    # Bottleneck indicators
    bottlenecks: List[str] = field(default_factory=list)
    performance_warnings: List[str] = field(default_factory=list)


@dataclass
class BottleneckAnalysis:
    """Detailed bottleneck analysis results."""
    bottleneck_type: str
    component: str
    severity: str  # 'low', 'medium', 'high', 'critical'
    impact_percentage: float
    description: str
    recommendations: List[str] = field(default_factory=list)
    metrics: Dict[str, float] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.utcnow)


class ProfiledFunction:
    """Decorator for profiling function performance."""
    
    def __init__(self, profiler: 'TrustScoringProfiler', name: Optional[str] = None):
        self.profiler = profiler
        self.name = name
    
    def __call__(self, func: Callable) -> Callable:
        function_name = self.name or f"{func.__module__}.{func.__qualname__}"
        
        async def async_wrapper(*args, **kwargs):
            with self.profiler.profile_function(function_name):
                return await func(*args, **kwargs)
        
        def sync_wrapper(*args, **kwargs):
            with self.profiler.profile_function(function_name):
                return func(*args, **kwargs)
        
        return async_wrapper if asyncio.iscoroutinefunction(func) else sync_wrapper


class MemoryTracker:
    """Track memory usage and detect leaks."""
    
    def __init__(self):
        self.baseline_memory = self._get_memory_usage()
        self.peak_memory = self.baseline_memory
        self.snapshots: List[Tuple[datetime, float]] = []
        self.leak_threshold_mb = 100  # 100MB increase indicates potential leak
    
    def _get_memory_usage(self) -> float:
        """Get current memory usage in MB."""
        process = psutil.Process()
        return process.memory_info().rss / 1024 / 1024
    
    def take_snapshot(self):
        """Take a memory usage snapshot."""
        current_memory = self._get_memory_usage()
        self.snapshots.append((datetime.utcnow(), current_memory))
        
        if current_memory > self.peak_memory:
            self.peak_memory = current_memory
        
        # Keep last 1000 snapshots
        if len(self.snapshots) > 1000:
            self.snapshots.pop(0)
    
    def detect_memory_leak(self) -> Optional[Dict[str, Any]]:
        """Detect potential memory leaks."""
        if len(self.snapshots) < 10:
            return None
        
        # Analyze recent trend
        recent_snapshots = self.snapshots[-10:]
        times = [snapshot[0] for snapshot in recent_snapshots]
        memories = [snapshot[1] for snapshot in recent_snapshots]
        
        # Simple linear regression to detect trend
        if len(memories) >= 2:
            x = np.arange(len(memories))
            slope = np.polyfit(x, memories, 1)[0]  # MB per snapshot
            
            # Convert to MB per hour
            if len(times) > 1:
                time_delta_hours = (times[-1] - times[0]).total_seconds() / 3600
                slope_per_hour = slope * len(memories) / max(time_delta_hours, 0.001)
                
                if slope_per_hour > 10:  # Growing more than 10MB/hour
                    return {
                        'leak_detected': True,
                        'growth_rate_mb_per_hour': slope_per_hour,
                        'current_memory_mb': memories[-1],
                        'baseline_memory_mb': self.baseline_memory,
                        'increase_from_baseline_mb': memories[-1] - self.baseline_memory,
                        'recommendation': 'Monitor memory usage and check for object retention'
                    }
        
        return None


class TrustScoringProfiler:
    """
    Comprehensive performance profiler for trust scoring systems
    with real-time monitoring and bottleneck identification.
    """
    
    def __init__(
        self,
        enable_detailed_profiling: bool = True,
        profile_interval_seconds: int = 60,
        max_history_minutes: int = 60
    ):
        self.enable_detailed_profiling = enable_detailed_profiling
        self.profile_interval = profile_interval_seconds
        self.max_history = max_history_minutes * 60 / profile_interval_seconds
        
        # Performance data storage
        self.metrics_history: deque = deque(maxlen=int(self.max_history))
        self.function_profiles: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self.bottleneck_history: List[BottleneckAnalysis] = []
        
        # Profiling state
        self.active_profiles: Dict[str, Dict[str, Any]] = {}
        self.profile_lock = threading.Lock()
        
        # Resource monitoring
        self.memory_tracker = MemoryTracker()
        self.cpu_monitor = CPUMonitor()
        
        # Background monitoring
        self.monitoring_task: Optional[asyncio.Task] = None
        self.active = False
        
        logger.info("TrustScoringProfiler initialized")
    
    async def start_monitoring(self):
        """Start continuous performance monitoring."""
        if self.active:
            return
        
        self.active = True
        self.monitoring_task = asyncio.create_task(self._monitoring_loop())
        logger.info("Performance monitoring started")
    
    async def stop_monitoring(self):
        """Stop performance monitoring."""
        self.active = False
        if self.monitoring_task:
            self.monitoring_task.cancel()
            try:
                await self.monitoring_task
            except asyncio.CancelledError:
                pass
        logger.info("Performance monitoring stopped")
    
    @contextmanager
    def profile_function(self, function_name: str):
        """Context manager for profiling function execution."""
        start_time = time.perf_counter()
        start_cpu = time.process_time()
        start_memory = self.memory_tracker._get_memory_usage()
        
        # Track active profile
        profile_id = f"{function_name}_{threading.get_ident()}"
        with self.profile_lock:
            self.active_profiles[profile_id] = {
                'function_name': function_name,
                'start_time': start_time,
                'start_cpu': start_cpu,
                'start_memory': start_memory
            }
        
        profiler = None
        if self.enable_detailed_profiling:
            profiler = cProfile.Profile()
            profiler.enable()
        
        try:
            yield
        finally:
            end_time = time.perf_counter()
            end_cpu = time.process_time()
            end_memory = self.memory_tracker._get_memory_usage()
            
            # Calculate metrics
            execution_time = (end_time - start_time) * 1000  # ms
            cpu_time = (end_cpu - start_cpu) * 1000  # ms
            memory_delta = end_memory - start_memory
            
            # Store function metrics
            function_metrics = {
                'execution_time_ms': execution_time,
                'cpu_time_ms': cpu_time,
                'memory_delta_mb': memory_delta,
                'timestamp': datetime.utcnow()
            }
            
            if profiler:
                profiler.disable()
                # Extract detailed profiling data
                s = io.StringIO()
                stats = pstats.Stats(profiler, stream=s)
                stats.sort_stats('cumulative')
                
                function_metrics['detailed_stats'] = s.getvalue()
            
            self.function_profiles[function_name].append(function_metrics)
            
            # Clean up active profile
            with self.profile_lock:
                if profile_id in self.active_profiles:
                    del self.active_profiles[profile_id]
    
    def profile_decorator(self, name: Optional[str] = None):
        """Decorator for automatic function profiling."""
        return ProfiledFunction(self, name)
    
    async def _monitoring_loop(self):
        """Main monitoring loop."""
        while self.active:
            try:
                # Collect system metrics
                metrics = await self._collect_system_metrics()
                self.metrics_history.append(metrics)
                
                # Memory tracking
                self.memory_tracker.take_snapshot()
                
                # Analyze for bottlenecks
                bottlenecks = await self._analyze_bottlenecks()
                if bottlenecks:
                    self.bottleneck_history.extend(bottlenecks)
                
                # Wait for next interval
                await asyncio.sleep(self.profile_interval)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Monitoring loop error: {e}")
                await asyncio.sleep(5)
    
    async def _collect_system_metrics(self) -> PerformanceMetrics:
        """Collect comprehensive system metrics."""
        # CPU and memory
        cpu_percent = psutil.cpu_percent(interval=1.0)
        memory_info = psutil.virtual_memory()
        process = psutil.Process()
        process_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        # Thread information
        active_threads = threading.active_count()
        
        # Trust scoring specific metrics
        trust_calc_rate = await self._calculate_trust_scoring_rate()
        cache_hit_rate = await self._get_cache_hit_rate()
        
        # Function call analysis
        function_calls, function_times = self._analyze_function_performance()
        
        metrics = PerformanceMetrics(
            execution_time_ms=0.0,  # Will be set per operation
            cpu_usage_percent=cpu_percent,
            memory_usage_mb=process_memory,
            memory_peak_mb=self.memory_tracker.peak_memory,
            trust_calculations_per_second=trust_calc_rate,
            cache_hit_rate=cache_hit_rate,
            active_threads=active_threads,
            function_calls=function_calls,
            function_times=function_times
        )
        
        return metrics
    
    async def _calculate_trust_scoring_rate(self) -> float:
        """Calculate trust calculations per second."""
        if len(self.metrics_history) < 2:
            return 0.0
        
        # Analyze recent function calls
        recent_metrics = list(self.metrics_history)[-5:]  # Last 5 measurements
        trust_calc_functions = [
            'calculate_trust_score',
            'calculate_comprehensive_trust_score',
            'process_trust_request'
        ]
        
        total_calls = 0
        total_time_seconds = 0
        
        for metrics in recent_metrics:
            for func_name, call_count in metrics.function_calls.items():
                if any(trust_func in func_name for trust_func in trust_calc_functions):
                    total_calls += call_count
            
            total_time_seconds += self.profile_interval
        
        return total_calls / max(total_time_seconds, 1.0)
    
    async def _get_cache_hit_rate(self) -> float:
        """Get cache hit rate from recent metrics."""
        # This would integrate with the actual cache system
        # For now, return a placeholder
        return 0.85  # 85% hit rate
    
    def _analyze_function_performance(self) -> Tuple[Dict[str, int], Dict[str, float]]:
        """Analyze function call patterns and performance."""
        function_calls = defaultdict(int)
        function_times = defaultdict(float)
        
        # Analyze recent function profiles
        cutoff_time = datetime.utcnow() - timedelta(minutes=5)
        
        for func_name, profiles in self.function_profiles.items():
            recent_profiles = [
                p for p in profiles
                if p['timestamp'] > cutoff_time
            ]
            
            if recent_profiles:
                function_calls[func_name] = len(recent_profiles)
                function_times[func_name] = sum(
                    p['execution_time_ms'] for p in recent_profiles
                ) / len(recent_profiles)
        
        return dict(function_calls), dict(function_times)
    
    async def _analyze_bottlenecks(self) -> List[BottleneckAnalysis]:
        """Analyze system for performance bottlenecks."""
        bottlenecks = []
        
        if not self.metrics_history:
            return bottlenecks
        
        latest_metrics = self.metrics_history[-1]
        
        # CPU bottleneck analysis
        if latest_metrics.cpu_usage_percent > 80:
            bottlenecks.append(BottleneckAnalysis(
                bottleneck_type="cpu",
                component="system",
                severity="high" if latest_metrics.cpu_usage_percent > 90 else "medium",
                impact_percentage=latest_metrics.cpu_usage_percent,
                description=f"High CPU usage: {latest_metrics.cpu_usage_percent:.1f}%",
                recommendations=[
                    "Consider increasing CPU resources",
                    "Optimize CPU-intensive algorithms",
                    "Implement better parallelization"
                ],
                metrics={"cpu_usage": latest_metrics.cpu_usage_percent}
            ))
        
        # Memory bottleneck analysis
        memory_leak_info = self.memory_tracker.detect_memory_leak()
        if memory_leak_info and memory_leak_info['leak_detected']:
            bottlenecks.append(BottleneckAnalysis(
                bottleneck_type="memory",
                component="application",
                severity="critical" if memory_leak_info['growth_rate_mb_per_hour'] > 50 else "high",
                impact_percentage=100.0,  # Memory leaks affect entire system
                description=f"Memory leak detected: {memory_leak_info['growth_rate_mb_per_hour']:.1f} MB/hour",
                recommendations=[
                    "Investigate object retention",
                    "Check for circular references", 
                    "Profile memory allocations",
                    memory_leak_info['recommendation']
                ],
                metrics=memory_leak_info
            ))
        
        # Function performance bottlenecks
        function_bottlenecks = self._analyze_function_bottlenecks()
        bottlenecks.extend(function_bottlenecks)
        
        # Trust scoring specific bottlenecks
        if latest_metrics.trust_calculations_per_second < 1000:  # Below target
            bottlenecks.append(BottleneckAnalysis(
                bottleneck_type="throughput",
                component="trust_scoring",
                severity="medium",
                impact_percentage=((1000 - latest_metrics.trust_calculations_per_second) / 1000) * 100,
                description=f"Low trust scoring throughput: {latest_metrics.trust_calculations_per_second:.1f}/sec",
                recommendations=[
                    "Optimize trust calculation algorithms",
                    "Implement better caching strategies",
                    "Consider parallel processing",
                    "Review database query performance"
                ],
                metrics={"throughput": latest_metrics.trust_calculations_per_second}
            ))
        
        return bottlenecks
    
    def _analyze_function_bottlenecks(self) -> List[BottleneckAnalysis]:
        """Analyze individual function performance for bottlenecks."""
        bottlenecks = []
        
        # Find slowest functions
        avg_execution_times = {}
        for func_name, profiles in self.function_profiles.items():
            if len(profiles) >= 5:  # Need sufficient samples
                recent_profiles = list(profiles)[-10:]  # Last 10 calls
                avg_time = sum(p['execution_time_ms'] for p in recent_profiles) / len(recent_profiles)
                avg_execution_times[func_name] = avg_time
        
        # Identify functions taking too long
        for func_name, avg_time in avg_execution_times.items():
            if avg_time > 100:  # More than 100ms average
                severity = "critical" if avg_time > 500 else "high" if avg_time > 200 else "medium"
                
                bottlenecks.append(BottleneckAnalysis(
                    bottleneck_type="function_performance",
                    component=func_name,
                    severity=severity,
                    impact_percentage=min(avg_time / 10, 100),  # Scale to percentage
                    description=f"Slow function execution: {func_name} ({avg_time:.1f}ms avg)",
                    recommendations=[
                        "Profile function internals",
                        "Optimize algorithm complexity",
                        "Consider caching results",
                        "Check for blocking operations"
                    ],
                    metrics={"avg_execution_time_ms": avg_time}
                ))
        
        return bottlenecks
    
    def get_performance_summary(self) -> Dict[str, Any]:
        """Get comprehensive performance summary."""
        if not self.metrics_history:
            return {'status': 'no_data'}
        
        latest_metrics = self.metrics_history[-1]
        recent_metrics = list(self.metrics_history)[-5:] if len(self.metrics_history) >= 5 else list(self.metrics_history)
        
        # Calculate averages
        avg_cpu = sum(m.cpu_usage_percent for m in recent_metrics) / len(recent_metrics)
        avg_memory = sum(m.memory_usage_mb for m in recent_metrics) / len(recent_metrics)
        avg_throughput = sum(m.trust_calculations_per_second for m in recent_metrics) / len(recent_metrics)
        
        # Recent bottlenecks
        recent_bottlenecks = [
            b for b in self.bottleneck_history[-10:]
            if b.timestamp > datetime.utcnow() - timedelta(hours=1)
        ]
        
        return {
            'timestamp': latest_metrics.timestamp.isoformat(),
            'current_performance': {
                'cpu_usage_percent': latest_metrics.cpu_usage_percent,
                'memory_usage_mb': latest_metrics.memory_usage_mb,
                'trust_calculations_per_second': latest_metrics.trust_calculations_per_second,
                'cache_hit_rate': latest_metrics.cache_hit_rate,
                'active_threads': latest_metrics.active_threads
            },
            'average_performance': {
                'cpu_usage_percent': avg_cpu,
                'memory_usage_mb': avg_memory,
                'trust_calculations_per_second': avg_throughput
            },
            'bottlenecks': {
                'count': len(recent_bottlenecks),
                'critical': len([b for b in recent_bottlenecks if b.severity == 'critical']),
                'high': len([b for b in recent_bottlenecks if b.severity == 'high']),
                'medium': len([b for b in recent_bottlenecks if b.severity == 'medium'])
            },
            'function_performance': dict(latest_metrics.function_times),
            'memory_analysis': self.memory_tracker.detect_memory_leak(),
            'recommendations': self._generate_optimization_recommendations()
        }
    
    def _generate_optimization_recommendations(self) -> List[str]:
        """Generate optimization recommendations based on analysis."""
        recommendations = []
        
        if not self.metrics_history:
            return recommendations
        
        latest_metrics = self.metrics_history[-1]
        
        # CPU optimization
        if latest_metrics.cpu_usage_percent > 75:
            recommendations.append("Consider CPU optimization: implement parallel processing for trust calculations")
        
        # Memory optimization
        if latest_metrics.memory_usage_mb > 1024:  # More than 1GB
            recommendations.append("Consider memory optimization: implement more aggressive caching strategies")
        
        # Throughput optimization
        if latest_metrics.trust_calculations_per_second < 1000:
            recommendations.append("Consider throughput optimization: implement batch processing and connection pooling")
        
        # Cache optimization
        if latest_metrics.cache_hit_rate < 0.8:
            recommendations.append("Consider cache optimization: improve cache warming and retention strategies")
        
        return recommendations
    
    def export_profile_data(self) -> Dict[str, Any]:
        """Export detailed profiling data for analysis."""
        return {
            'metrics_history': [
                {
                    'timestamp': m.timestamp.isoformat(),
                    'cpu_usage_percent': m.cpu_usage_percent,
                    'memory_usage_mb': m.memory_usage_mb,
                    'trust_calculations_per_second': m.trust_calculations_per_second,
                    'cache_hit_rate': m.cache_hit_rate,
                    'function_times': m.function_times
                }
                for m in self.metrics_history
            ],
            'function_profiles': {
                func_name: [
                    {
                        'timestamp': p['timestamp'].isoformat(),
                        'execution_time_ms': p['execution_time_ms'],
                        'cpu_time_ms': p['cpu_time_ms'],
                        'memory_delta_mb': p['memory_delta_mb']
                    }
                    for p in profiles
                ]
                for func_name, profiles in self.function_profiles.items()
            },
            'bottleneck_history': [
                {
                    'timestamp': b.timestamp.isoformat(),
                    'type': b.bottleneck_type,
                    'component': b.component,
                    'severity': b.severity,
                    'impact_percentage': b.impact_percentage,
                    'description': b.description,
                    'recommendations': b.recommendations
                }
                for b in self.bottleneck_history
            ]
        }


class CPUMonitor:
    """Monitor CPU usage patterns."""
    
    def __init__(self):
        self.cpu_history = deque(maxlen=100)
    
    def get_cpu_trend(self) -> Dict[str, float]:
        """Get CPU usage trend analysis."""
        if len(self.cpu_history) < 5:
            return {'trend': 0.0, 'volatility': 0.0}
        
        recent_cpu = list(self.cpu_history)[-10:]
        
        # Simple trend analysis
        trend = (recent_cpu[-1] - recent_cpu[0]) / len(recent_cpu)
        volatility = np.std(recent_cpu) if len(recent_cpu) > 1 else 0.0
        
        return {
            'trend': trend,
            'volatility': volatility,
            'current': recent_cpu[-1],
            'average': np.mean(recent_cpu)
        }


# Export for external use
__all__ = [
    'TrustScoringProfiler',
    'PerformanceMetrics',
    'BottleneckAnalysis',
    'ProfiledFunction',
    'MemoryTracker'
]