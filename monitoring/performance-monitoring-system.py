"""
Comprehensive Performance Monitoring System

Unified performance monitoring for AI/ML models, executive dashboards,
and trust scoring engines with real-time metrics and alerting.
"""

import asyncio
import logging
import time
import json
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Callable, Union
from collections import defaultdict, deque
import numpy as np
import pandas as pd
from concurrent.futures import ThreadPoolExecutor
import psutil
import aioredis
from prometheus_client import Counter, Histogram, Gauge, CollectorRegistry, generate_latest
import aiohttp

from ..ai-services.services.threat-detection-ml.monitoring.model_performance_monitor import ModelPerformanceMonitor
from ..ai-services.services.trust-scoring.optimization.performance_profiler import TrustScoringProfiler
from ..app.lib.hooks.use-performance-optimizer import usePerformanceOptimizer

logger = logging.getLogger(__name__)


@dataclass
class SystemPerformanceMetrics:
    """Comprehensive system performance metrics."""
    timestamp: datetime = field(default_factory=datetime.utcnow)
    
    # System-wide metrics
    overall_health_score: float = 0.0
    system_cpu_percent: float = 0.0
    system_memory_percent: float = 0.0
    system_disk_io_mb_per_sec: float = 0.0
    network_io_mb_per_sec: float = 0.0
    
    # AI/ML Model Performance
    model_inference_time_p95_ms: float = 0.0
    model_throughput_per_second: float = 0.0
    model_accuracy_score: float = 0.0
    model_drift_alerts: int = 0
    
    # Executive Dashboard Performance
    dashboard_load_time_ms: float = 0.0
    dashboard_render_time_ms: float = 0.0
    dashboard_cache_hit_rate: float = 0.0
    dashboard_active_users: int = 0
    
    # Trust Scoring Performance
    trust_calc_throughput_per_second: float = 0.0
    trust_calc_latency_p95_ms: float = 0.0
    trust_cache_hit_rate: float = 0.0
    trust_scoring_queue_size: int = 0
    
    # Service Integration
    api_response_time_p95_ms: float = 0.0
    database_query_time_p95_ms: float = 0.0
    external_service_latency_ms: float = 0.0
    
    # Alerts and Issues
    active_alerts: int = 0
    critical_alerts: int = 0
    performance_warnings: List[str] = field(default_factory=list)


@dataclass
class PerformanceBudget:
    """Performance budgets and SLA targets."""
    # AI/ML Model Budgets
    model_inference_sla_ms: float = 50.0
    model_throughput_sla: float = 1000.0
    model_accuracy_sla: float = 0.95
    
    # Dashboard Budgets
    dashboard_load_sla_ms: float = 2000.0
    dashboard_render_sla_ms: float = 100.0
    dashboard_cache_sla: float = 0.80
    
    # Trust Scoring Budgets
    trust_calc_sla_ms: float = 10.0
    trust_throughput_sla: float = 10000.0
    trust_cache_sla: float = 0.85
    
    # System Resource Budgets
    cpu_usage_limit_percent: float = 80.0
    memory_usage_limit_percent: float = 85.0
    disk_io_limit_mb_per_sec: float = 100.0


class AlertManager:
    """Manage performance alerts and notifications."""
    
    def __init__(self):
        self.active_alerts: Dict[str, Dict[str, Any]] = {}
        self.alert_history: deque = deque(maxlen=1000)
        self.notification_callbacks: List[Callable] = []
        self.cooldown_periods: Dict[str, datetime] = {}
        
    def add_notification_callback(self, callback: Callable):
        """Add callback for alert notifications."""
        self.notification_callbacks.append(callback)
    
    async def trigger_alert(
        self,
        alert_id: str,
        severity: str,
        component: str,
        message: str,
        metrics: Dict[str, Any],
        cooldown_minutes: int = 15
    ):
        """Trigger a performance alert."""
        # Check cooldown
        if alert_id in self.cooldown_periods:
            if datetime.utcnow() < self.cooldown_periods[alert_id]:
                return
        
        alert = {
            'alert_id': alert_id,
            'severity': severity,  # 'info', 'warning', 'critical'
            'component': component,
            'message': message,
            'metrics': metrics,
            'timestamp': datetime.utcnow(),
            'acknowledged': False
        }
        
        # Store alert
        self.active_alerts[alert_id] = alert
        self.alert_history.append(alert.copy())
        
        # Set cooldown
        self.cooldown_periods[alert_id] = datetime.utcnow() + timedelta(minutes=cooldown_minutes)
        
        # Notify callbacks
        for callback in self.notification_callbacks:
            try:
                await callback(alert)
            except Exception as e:
                logger.error(f"Alert notification callback failed: {e}")
        
        logger.warning(f"Performance alert triggered: {alert_id} - {message}")
    
    def acknowledge_alert(self, alert_id: str):
        """Acknowledge an alert."""
        if alert_id in self.active_alerts:
            self.active_alerts[alert_id]['acknowledged'] = True
            logger.info(f"Alert acknowledged: {alert_id}")
    
    def resolve_alert(self, alert_id: str):
        """Resolve an alert."""
        if alert_id in self.active_alerts:
            resolved_alert = self.active_alerts.pop(alert_id)
            resolved_alert['resolved_at'] = datetime.utcnow()
            logger.info(f"Alert resolved: {alert_id}")
    
    def get_active_alerts(self) -> List[Dict[str, Any]]:
        """Get all active alerts."""
        return list(self.active_alerts.values())
    
    def get_alert_summary(self) -> Dict[str, int]:
        """Get alert summary statistics."""
        active_alerts = list(self.active_alerts.values())
        return {
            'total_active': len(active_alerts),
            'critical': len([a for a in active_alerts if a['severity'] == 'critical']),
            'warning': len([a for a in active_alerts if a['severity'] == 'warning']),
            'info': len([a for a in active_alerts if a['severity'] == 'info']),
            'unacknowledged': len([a for a in active_alerts if not a['acknowledged']])
        }


class MetricsCollector:
    """Collect metrics from various system components."""
    
    def __init__(self):
        # Prometheus metrics
        self.registry = CollectorRegistry()
        
        # System metrics
        self.cpu_usage = Gauge('system_cpu_usage_percent', 'System CPU usage', registry=self.registry)
        self.memory_usage = Gauge('system_memory_usage_percent', 'System memory usage', registry=self.registry)
        
        # AI/ML model metrics
        self.model_inference_time = Histogram('model_inference_time_seconds', 'Model inference time', ['model_id'], registry=self.registry)
        self.model_throughput = Gauge('model_throughput_per_second', 'Model throughput', ['model_id'], registry=self.registry)
        
        # Dashboard metrics
        self.dashboard_load_time = Histogram('dashboard_load_time_seconds', 'Dashboard load time', ['user_role'], registry=self.registry)
        self.dashboard_cache_hits = Counter('dashboard_cache_hits_total', 'Dashboard cache hits', registry=self.registry)
        
        # Trust scoring metrics
        self.trust_calc_time = Histogram('trust_calculation_time_seconds', 'Trust calculation time', registry=self.registry)
        self.trust_throughput = Gauge('trust_throughput_per_second', 'Trust calculation throughput', registry=self.registry)
        
        # Component references
        self.model_monitor: Optional[ModelPerformanceMonitor] = None
        self.trust_profiler: Optional[TrustScoringProfiler] = None
        
    def set_model_monitor(self, monitor: ModelPerformanceMonitor):
        """Set model performance monitor reference."""
        self.model_monitor = monitor
    
    def set_trust_profiler(self, profiler: TrustScoringProfiler):
        """Set trust scoring profiler reference."""
        self.trust_profiler = profiler
    
    async def collect_system_metrics(self) -> SystemPerformanceMetrics:
        """Collect comprehensive system metrics."""
        # System resource metrics
        cpu_percent = psutil.cpu_percent(interval=1.0)
        memory = psutil.virtual_memory()
        disk_io = psutil.disk_io_counters()
        network_io = psutil.net_io_counters()
        
        # Update Prometheus metrics
        self.cpu_usage.set(cpu_percent)
        self.memory_usage.set(memory.percent)
        
        metrics = SystemPerformanceMetrics(
            system_cpu_percent=cpu_percent,
            system_memory_percent=memory.percent
        )
        
        # Collect AI/ML model metrics
        if self.model_monitor:
            model_metrics = await self._collect_model_metrics()
            metrics.model_inference_time_p95_ms = model_metrics.get('inference_time_p95', 0.0)
            metrics.model_throughput_per_second = model_metrics.get('throughput', 0.0)
            metrics.model_accuracy_score = model_metrics.get('accuracy', 0.0)
            metrics.model_drift_alerts = model_metrics.get('drift_alerts', 0)
        
        # Collect trust scoring metrics
        if self.trust_profiler:
            trust_metrics = await self._collect_trust_metrics()
            metrics.trust_calc_throughput_per_second = trust_metrics.get('throughput', 0.0)
            metrics.trust_calc_latency_p95_ms = trust_metrics.get('latency_p95', 0.0)
            metrics.trust_cache_hit_rate = trust_metrics.get('cache_hit_rate', 0.0)
            metrics.trust_scoring_queue_size = trust_metrics.get('queue_size', 0)
        
        # Dashboard metrics would be collected from frontend performance data
        # This would typically come from browser performance APIs or APM tools
        
        # Calculate overall health score
        metrics.overall_health_score = self._calculate_health_score(metrics)
        
        return metrics
    
    async def _collect_model_metrics(self) -> Dict[str, Any]:
        """Collect AI/ML model performance metrics."""
        if not self.model_monitor:
            return {}
        
        try:
            # Get metrics from all registered models
            all_metrics = {}
            for model_id in self.model_monitor._registered_models:
                model_metrics = self.model_monitor.get_current_metrics(model_id)
                if model_metrics:
                    all_metrics[model_id] = {
                        'inference_time_p95': model_metrics.inference_time_p95,
                        'throughput': model_metrics.throughput_per_second,
                        'accuracy': model_metrics.accuracy,
                        'error_rate': model_metrics.error_rate_percent
                    }
                    
                    # Update Prometheus metrics
                    self.model_throughput.labels(model_id=model_id).set(model_metrics.throughput_per_second)
            
            # Aggregate metrics
            if all_metrics:
                aggregated = {
                    'inference_time_p95': np.mean([m['inference_time_p95'] for m in all_metrics.values()]),
                    'throughput': sum(m['throughput'] for m in all_metrics.values()),
                    'accuracy': np.mean([m['accuracy'] for m in all_metrics.values()]),
                    'drift_alerts': 0  # Would come from drift detector
                }
                return aggregated
        
        except Exception as e:
            logger.error(f"Failed to collect model metrics: {e}")
        
        return {}
    
    async def _collect_trust_metrics(self) -> Dict[str, Any]:
        """Collect trust scoring performance metrics."""
        if not self.trust_profiler:
            return {}
        
        try:
            performance_summary = self.trust_profiler.get_performance_summary()
            
            if 'current_performance' in performance_summary:
                current = performance_summary['current_performance']
                return {
                    'throughput': current.get('trust_calculations_per_second', 0.0),
                    'latency_p95': current.get('avg_execution_time_ms', 0.0),  # Simplified
                    'cache_hit_rate': current.get('cache_hit_rate', 0.0),
                    'queue_size': 0  # Would come from actual queue monitoring
                }
        
        except Exception as e:
            logger.error(f"Failed to collect trust metrics: {e}")
        
        return {}
    
    def _calculate_health_score(self, metrics: SystemPerformanceMetrics) -> float:
        """Calculate overall system health score (0-100)."""
        score = 100.0
        
        # System resource penalties
        if metrics.system_cpu_percent > 80:
            score -= (metrics.system_cpu_percent - 80) * 0.5
        
        if metrics.system_memory_percent > 85:
            score -= (metrics.system_memory_percent - 85) * 0.3
        
        # Model performance penalties
        if metrics.model_inference_time_p95_ms > 50:
            score -= (metrics.model_inference_time_p95_ms - 50) * 0.1
        
        if metrics.model_accuracy_score < 0.95 and metrics.model_accuracy_score > 0:
            score -= (0.95 - metrics.model_accuracy_score) * 100
        
        # Trust scoring penalties
        if metrics.trust_calc_latency_p95_ms > 10:
            score -= (metrics.trust_calc_latency_p95_ms - 10) * 0.2
        
        if metrics.trust_calc_throughput_per_second < 10000:
            score -= (10000 - metrics.trust_calc_throughput_per_second) * 0.001
        
        return max(0.0, min(100.0, score))
    
    def get_prometheus_metrics(self) -> str:
        """Get metrics in Prometheus format."""
        return generate_latest(self.registry)


class PerformanceMonitoringSystem:
    """
    Comprehensive performance monitoring system integrating all components
    with real-time metrics, alerting, and optimization recommendations.
    """
    
    def __init__(
        self,
        monitoring_interval_seconds: int = 30,
        redis_url: Optional[str] = None
    ):
        self.monitoring_interval = monitoring_interval_seconds
        self.redis_url = redis_url
        
        # Components
        self.metrics_collector = MetricsCollector()
        self.alert_manager = AlertManager()
        self.performance_budget = PerformanceBudget()
        
        # Data storage
        self.metrics_history: deque = deque(maxlen=2880)  # 24 hours at 30sec intervals
        self.performance_trends: Dict[str, List[float]] = defaultdict(list)
        
        # Monitoring state
        self.monitoring_task: Optional[asyncio.Task] = None
        self.active = False
        
        # Redis connection
        self.redis_client: Optional[aioredis.Redis] = None
        
        # Set up alert notifications
        self.alert_manager.add_notification_callback(self._handle_critical_alerts)
        
        logger.info("Performance Monitoring System initialized")
    
    async def start(self):
        """Start the performance monitoring system."""
        if self.active:
            return
        
        # Initialize Redis connection
        if self.redis_url:
            try:
                self.redis_client = await aioredis.from_url(self.redis_url)
                await self.redis_client.ping()
                logger.info("Redis connection established")
            except Exception as e:
                logger.error(f"Failed to connect to Redis: {e}")
        
        self.active = True
        self.monitoring_task = asyncio.create_task(self._monitoring_loop())
        
        logger.info("Performance monitoring started")
    
    async def stop(self):
        """Stop the performance monitoring system."""
        self.active = False
        
        if self.monitoring_task:
            self.monitoring_task.cancel()
            try:
                await self.monitoring_task
            except asyncio.CancelledError:
                pass
        
        if self.redis_client:
            await self.redis_client.close()
        
        logger.info("Performance monitoring stopped")
    
    async def _monitoring_loop(self):
        """Main monitoring loop."""
        while self.active:
            try:
                # Collect metrics
                metrics = await self.metrics_collector.collect_system_metrics()
                self.metrics_history.append(metrics)
                
                # Store metrics in Redis
                await self._store_metrics_redis(metrics)
                
                # Check SLA violations
                await self._check_sla_violations(metrics)
                
                # Update performance trends
                self._update_performance_trends(metrics)
                
                # Generate optimization recommendations
                recommendations = await self._generate_optimization_recommendations(metrics)
                
                if recommendations:
                    logger.info(f"Performance recommendations: {', '.join(recommendations)}")
                
                await asyncio.sleep(self.monitoring_interval)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Monitoring loop error: {e}")
                await asyncio.sleep(5)
    
    async def _store_metrics_redis(self, metrics: SystemPerformanceMetrics):
        """Store metrics in Redis for external consumption."""
        if not self.redis_client:
            return
        
        try:
            metrics_data = {
                'timestamp': metrics.timestamp.isoformat(),
                'overall_health_score': metrics.overall_health_score,
                'system_cpu_percent': metrics.system_cpu_percent,
                'system_memory_percent': metrics.system_memory_percent,
                'model_inference_time_p95_ms': metrics.model_inference_time_p95_ms,
                'model_throughput_per_second': metrics.model_throughput_per_second,
                'trust_calc_throughput_per_second': metrics.trust_calc_throughput_per_second,
                'trust_calc_latency_p95_ms': metrics.trust_calc_latency_p95_ms,
                'active_alerts': metrics.active_alerts,
                'critical_alerts': metrics.critical_alerts
            }
            
            # Store current metrics
            await self.redis_client.setex(
                'performance:current_metrics',
                300,  # 5 minute TTL
                json.dumps(metrics_data)
            )
            
            # Store in time series
            timestamp_key = f"performance:metrics:{int(metrics.timestamp.timestamp())}"
            await self.redis_client.setex(
                timestamp_key,
                3600,  # 1 hour TTL
                json.dumps(metrics_data)
            )
            
        except Exception as e:
            logger.error(f"Failed to store metrics in Redis: {e}")
    
    async def _check_sla_violations(self, metrics: SystemPerformanceMetrics):
        """Check for SLA violations and trigger alerts."""
        budget = self.performance_budget
        
        # Model inference SLA
        if metrics.model_inference_time_p95_ms > budget.model_inference_sla_ms:
            await self.alert_manager.trigger_alert(
                alert_id="model_inference_sla_violation",
                severity="critical",
                component="ai_models",
                message=f"Model inference time exceeded SLA: {metrics.model_inference_time_p95_ms:.1f}ms > {budget.model_inference_sla_ms}ms",
                metrics={"current": metrics.model_inference_time_p95_ms, "sla": budget.model_inference_sla_ms}
            )
        
        # Trust scoring SLA
        if metrics.trust_calc_latency_p95_ms > budget.trust_calc_sla_ms:
            await self.alert_manager.trigger_alert(
                alert_id="trust_scoring_sla_violation",
                severity="critical",
                component="trust_scoring",
                message=f"Trust scoring latency exceeded SLA: {metrics.trust_calc_latency_p95_ms:.1f}ms > {budget.trust_calc_sla_ms}ms",
                metrics={"current": metrics.trust_calc_latency_p95_ms, "sla": budget.trust_calc_sla_ms}
            )
        
        # System resource SLAs
        if metrics.system_cpu_percent > budget.cpu_usage_limit_percent:
            await self.alert_manager.trigger_alert(
                alert_id="high_cpu_usage",
                severity="warning",
                component="system",
                message=f"High CPU usage: {metrics.system_cpu_percent:.1f}% > {budget.cpu_usage_limit_percent}%",
                metrics={"current": metrics.system_cpu_percent, "limit": budget.cpu_usage_limit_percent}
            )
        
        if metrics.system_memory_percent > budget.memory_usage_limit_percent:
            await self.alert_manager.trigger_alert(
                alert_id="high_memory_usage",
                severity="warning",
                component="system",
                message=f"High memory usage: {metrics.system_memory_percent:.1f}% > {budget.memory_usage_limit_percent}%",
                metrics={"current": metrics.system_memory_percent, "limit": budget.memory_usage_limit_percent}
            )
    
    def _update_performance_trends(self, metrics: SystemPerformanceMetrics):
        """Update performance trend analysis."""
        trends = self.performance_trends
        
        # Track key metrics
        trends['health_score'].append(metrics.overall_health_score)
        trends['cpu_usage'].append(metrics.system_cpu_percent)
        trends['memory_usage'].append(metrics.system_memory_percent)
        trends['model_inference_time'].append(metrics.model_inference_time_p95_ms)
        trends['trust_calc_throughput'].append(metrics.trust_calc_throughput_per_second)
        
        # Keep last 100 data points for trend analysis
        for key in trends:
            if len(trends[key]) > 100:
                trends[key].pop(0)
    
    async def _generate_optimization_recommendations(
        self,
        metrics: SystemPerformanceMetrics
    ) -> List[str]:
        """Generate optimization recommendations based on metrics."""
        recommendations = []
        
        # CPU optimization
        if metrics.system_cpu_percent > 75:
            recommendations.append("Consider horizontal scaling or CPU optimization")
        
        # Memory optimization
        if metrics.system_memory_percent > 80:
            recommendations.append("Implement memory optimization or increase available memory")
        
        # Model performance optimization
        if metrics.model_inference_time_p95_ms > 30:
            recommendations.append("Optimize AI model inference time through quantization or caching")
        
        if metrics.model_throughput_per_second < 500:
            recommendations.append("Consider model parallelization or batch processing optimization")
        
        # Trust scoring optimization
        if metrics.trust_calc_throughput_per_second < 5000:
            recommendations.append("Optimize trust scoring with better caching and parallel processing")
        
        if metrics.trust_calc_latency_p95_ms > 5:
            recommendations.append("Consider trust score precomputation and intelligent caching")
        
        # Dashboard optimization
        if metrics.dashboard_load_time_ms > 1500:
            recommendations.append("Optimize dashboard with code splitting and data virtualization")
        
        return recommendations
    
    async def _handle_critical_alerts(self, alert: Dict[str, Any]):
        """Handle critical performance alerts."""
        if alert['severity'] == 'critical':
            # Could integrate with external alerting systems
            # For now, just log
            logger.critical(f"CRITICAL ALERT: {alert['message']}")
            
            # In production, this might trigger:
            # - PagerDuty notifications
            # - Slack/Teams messages
            # - Auto-scaling actions
            # - Circuit breaker activation
    
    def get_performance_dashboard_data(self) -> Dict[str, Any]:
        """Get data for performance dashboard."""
        if not self.metrics_history:
            return {'status': 'no_data'}
        
        latest_metrics = self.metrics_history[-1]
        
        # Calculate trends
        trends = {}
        for metric_name, values in self.performance_trends.items():
            if len(values) >= 2:
                recent_avg = np.mean(values[-10:]) if len(values) >= 10 else np.mean(values)
                older_avg = np.mean(values[-20:-10]) if len(values) >= 20 else recent_avg
                trend = ((recent_avg - older_avg) / max(older_avg, 0.001)) * 100
                trends[metric_name] = {
                    'current': values[-1],
                    'trend_percent': trend,
                    'direction': 'up' if trend > 1 else 'down' if trend < -1 else 'stable'
                }
        
        return {
            'timestamp': latest_metrics.timestamp.isoformat(),
            'overall_health_score': latest_metrics.overall_health_score,
            'system_metrics': {
                'cpu_percent': latest_metrics.system_cpu_percent,
                'memory_percent': latest_metrics.system_memory_percent,
                'health_status': 'healthy' if latest_metrics.overall_health_score > 80 else 'degraded'
            },
            'ai_model_metrics': {
                'inference_time_p95_ms': latest_metrics.model_inference_time_p95_ms,
                'throughput_per_second': latest_metrics.model_throughput_per_second,
                'accuracy_score': latest_metrics.model_accuracy_score,
                'drift_alerts': latest_metrics.model_drift_alerts
            },
            'trust_scoring_metrics': {
                'throughput_per_second': latest_metrics.trust_calc_throughput_per_second,
                'latency_p95_ms': latest_metrics.trust_calc_latency_p95_ms,
                'cache_hit_rate': latest_metrics.trust_cache_hit_rate,
                'queue_size': latest_metrics.trust_scoring_queue_size
            },
            'dashboard_metrics': {
                'load_time_ms': latest_metrics.dashboard_load_time_ms,
                'render_time_ms': latest_metrics.dashboard_render_time_ms,
                'cache_hit_rate': latest_metrics.dashboard_cache_hit_rate,
                'active_users': latest_metrics.dashboard_active_users
            },
            'alerts': self.alert_manager.get_alert_summary(),
            'trends': trends,
            'sla_status': {
                'model_inference_sla_met': latest_metrics.model_inference_time_p95_ms <= self.performance_budget.model_inference_sla_ms,
                'trust_scoring_sla_met': latest_metrics.trust_calc_latency_p95_ms <= self.performance_budget.trust_calc_sla_ms,
                'dashboard_sla_met': latest_metrics.dashboard_load_time_ms <= self.performance_budget.dashboard_load_sla_ms
            }
        }
    
    async def get_performance_report(self, hours: int = 24) -> Dict[str, Any]:
        """Generate comprehensive performance report."""
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        
        # Filter metrics by time period
        period_metrics = [
            m for m in self.metrics_history
            if m.timestamp > cutoff_time
        ]
        
        if not period_metrics:
            return {'error': 'No data available for the specified period'}
        
        # Calculate aggregated statistics
        health_scores = [m.overall_health_score for m in period_metrics]
        cpu_usage = [m.system_cpu_percent for m in period_metrics]
        memory_usage = [m.system_memory_percent for m in period_metrics]
        
        model_inference_times = [m.model_inference_time_p95_ms for m in period_metrics if m.model_inference_time_p95_ms > 0]
        trust_throughput = [m.trust_calc_throughput_per_second for m in period_metrics if m.trust_calc_throughput_per_second > 0]
        
        report = {
            'period_hours': hours,
            'data_points': len(period_metrics),
            'health_summary': {
                'avg_health_score': np.mean(health_scores),
                'min_health_score': np.min(health_scores),
                'health_below_80_percent': (np.array(health_scores) < 80).mean() * 100
            },
            'resource_usage': {
                'avg_cpu_percent': np.mean(cpu_usage),
                'max_cpu_percent': np.max(cpu_usage),
                'avg_memory_percent': np.mean(memory_usage),
                'max_memory_percent': np.max(memory_usage)
            },
            'sla_compliance': {
                'model_inference_sla_compliance': (np.array(model_inference_times) <= self.performance_budget.model_inference_sla_ms).mean() * 100 if model_inference_times else 0,
                'trust_scoring_meets_target': (np.array(trust_throughput) >= self.performance_budget.trust_throughput_sla).mean() * 100 if trust_throughput else 0
            },
            'alert_summary': {
                'total_alerts_in_period': len([a for a in self.alert_manager.alert_history if a['timestamp'] > cutoff_time]),
                'critical_alerts': len([a for a in self.alert_manager.alert_history if a['timestamp'] > cutoff_time and a['severity'] == 'critical']),
                'current_active_alerts': len(self.alert_manager.active_alerts)
            },
            'recommendations': await self._generate_optimization_recommendations(period_metrics[-1])
        }
        
        return report


# Export for external use
__all__ = [
    'PerformanceMonitoringSystem',
    'SystemPerformanceMetrics',
    'PerformanceBudget',
    'AlertManager',
    'MetricsCollector'
]