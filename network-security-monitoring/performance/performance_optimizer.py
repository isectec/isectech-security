#!/usr/bin/env python3
"""
iSECTECH NSM Performance Optimizer
Comprehensive performance monitoring, analysis, and optimization for NSM components
"""

import asyncio
import json
import logging
import psutil
import sqlite3
import time
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path
import subprocess
import yaml
import redis
import requests
from prometheus_client import CollectorRegistry, Gauge, Counter, Histogram, generate_latest


@dataclass
class PerformanceMetric:
    """Performance metric data structure"""
    metric_id: str
    component: str
    metric_name: str
    value: float
    timestamp: datetime
    unit: str
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


@dataclass
class OptimizationRecommendation:
    """Optimization recommendation structure"""
    recommendation_id: str
    component: str
    category: str  # cpu, memory, disk, network, configuration
    priority: str  # critical, high, medium, low
    title: str
    description: str
    impact: str
    implementation_effort: str
    estimated_improvement: str
    commands: List[str] = None
    
    def __post_init__(self):
        if self.commands is None:
            self.commands = []


class NSMPerformanceOptimizer:
    """Main performance optimizer and monitor"""
    
    def __init__(self, config_path: str = "/etc/nsm/performance_optimizer.yaml"):
        self.config_path = config_path
        self.config = self._load_config()
        self.logger = self._setup_logging()
        
        # Database for metrics storage
        self.database = self._init_database()
        
        # Redis for real-time metrics
        self.redis_client = self._init_redis()
        
        # Prometheus registry
        self.prometheus_registry = CollectorRegistry()
        self._init_prometheus_metrics()
        
        # Component endpoints
        self.component_endpoints = self._get_component_endpoints()
        
        # Performance thresholds
        self.thresholds = self.config.get('thresholds', {})
        
        # Metrics collection
        self.metrics_history = defaultdict(lambda: deque(maxlen=1000))
        self.current_metrics = {}
        
        # Optimization recommendations
        self.recommendations = []
        
        # Monitoring intervals
        self.collection_interval = self.config.get('collection_interval', 30)
        self.analysis_interval = self.config.get('analysis_interval', 300)
        
        # Thread pool for parallel monitoring
        self.executor = ThreadPoolExecutor(max_workers=8)
        
        # Control flags
        self.running = False
        self.shutdown_event = asyncio.Event()
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from YAML file"""
        try:
            with open(self.config_path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            print(f"Error loading performance optimizer config: {e}")
            return {}
    
    def _setup_logging(self) -> logging.Logger:
        """Setup logging configuration"""
        logger = logging.getLogger('NSMPerformanceOptimizer')
        logger.setLevel(logging.INFO)
        
        # Console handler
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        
        # File handler
        file_handler = logging.FileHandler('/var/log/nsm/performance_optimizer.log')
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        
        return logger
    
    def _init_database(self) -> sqlite3.Connection:
        """Initialize metrics database"""
        db_path = "/var/lib/nsm/performance_metrics.db"
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        
        conn = sqlite3.connect(db_path, check_same_thread=False)
        
        # Create metrics table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS performance_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                metric_id TEXT,
                component TEXT,
                metric_name TEXT,
                value REAL,
                timestamp DATETIME,
                unit TEXT,
                metadata TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create recommendations table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS optimization_recommendations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                recommendation_id TEXT UNIQUE,
                component TEXT,
                category TEXT,
                priority TEXT,
                title TEXT,
                description TEXT,
                impact TEXT,
                implementation_effort TEXT,
                estimated_improvement TEXT,
                commands TEXT,
                status TEXT DEFAULT 'pending',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                implemented_at DATETIME
            )
        ''')
        
        # Create optimization history table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS optimization_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                component TEXT,
                optimization_type TEXT,
                before_value REAL,
                after_value REAL,
                improvement_percent REAL,
                timestamp DATETIME,
                notes TEXT
            )
        ''')
        
        conn.commit()
        return conn
    
    def _init_redis(self) -> Optional[redis.Redis]:
        """Initialize Redis connection for real-time metrics"""
        try:
            redis_config = self.config.get('redis', {})
            if not redis_config.get('enabled', False):
                return None
                
            return redis.Redis(
                host=redis_config['host'],
                port=redis_config['port'],
                db=redis_config.get('db', 11),
                password=redis_config.get('password'),
                decode_responses=True,
                socket_timeout=30
            )
        except Exception as e:
            self.logger.error(f"Failed to initialize Redis: {e}")
            return None
    
    def _init_prometheus_metrics(self):
        """Initialize Prometheus metrics"""
        # System metrics
        self.cpu_usage = Gauge('nsm_cpu_usage_percent', 'CPU usage percentage', ['component'], registry=self.prometheus_registry)
        self.memory_usage = Gauge('nsm_memory_usage_bytes', 'Memory usage in bytes', ['component'], registry=self.prometheus_registry)
        self.disk_usage = Gauge('nsm_disk_usage_percent', 'Disk usage percentage', ['component', 'mount'], registry=self.prometheus_registry)
        self.network_io = Gauge('nsm_network_io_bytes', 'Network I/O in bytes', ['component', 'direction'], registry=self.prometheus_registry)
        
        # Performance metrics
        self.event_processing_rate = Gauge('nsm_event_processing_rate', 'Event processing rate per second', ['component'], registry=self.prometheus_registry)
        self.response_time = Histogram('nsm_response_time_seconds', 'Response time in seconds', ['component', 'endpoint'], registry=self.prometheus_registry)
        self.queue_size = Gauge('nsm_queue_size', 'Queue size', ['component', 'queue'], registry=self.prometheus_registry)
        self.error_rate = Gauge('nsm_error_rate', 'Error rate percentage', ['component'], registry=self.prometheus_registry)
        
        # Database metrics
        self.db_connections = Gauge('nsm_database_connections', 'Database connection count', ['component'], registry=self.prometheus_registry)
        self.db_query_time = Histogram('nsm_database_query_seconds', 'Database query time', ['component', 'operation'], registry=self.prometheus_registry)
        
        # Cache metrics
        self.cache_hit_rate = Gauge('nsm_cache_hit_rate', 'Cache hit rate percentage', ['component'], registry=self.prometheus_registry)
        self.cache_size = Gauge('nsm_cache_size_bytes', 'Cache size in bytes', ['component'], registry=self.prometheus_registry)
    
    def _get_component_endpoints(self) -> Dict[str, Dict[str, str]]:
        """Get component endpoints for monitoring"""
        return {
            'signature_detection': {
                'health': 'http://localhost:8437/health',
                'metrics': 'http://localhost:8088/metrics',
                'stats': 'http://localhost:8437/api/v1/stats'
            },
            'anomaly_detection': {
                'health': 'http://localhost:8441/health',
                'metrics': 'http://localhost:9090/metrics',
                'stats': 'http://localhost:8441/api/v1/stats'
            },
            'behavioral_analysis': {
                'health': 'http://localhost:8444/health',
                'metrics': 'http://localhost:9094/metrics',
                'stats': 'http://localhost:8444/api/v1/stats'
            },
            'encrypted_analysis': {
                'health': 'http://localhost:8445/health',
                'metrics': 'http://localhost:9091/metrics',
                'stats': 'http://localhost:8445/api/v1/stats'
            },
            'asset_discovery': {
                'health': 'http://localhost:8446/health',
                'metrics': 'http://localhost:9092/metrics',
                'stats': 'http://localhost:8446/api/v1/stats'
            },
            'vulnerability_correlation': {
                'health': 'http://localhost:8447/health',
                'metrics': 'http://localhost:9093/metrics',
                'stats': 'http://localhost:8447/api/v1/stats'
            },
            'siem_integration': {
                'health': 'http://localhost:8448/health',
                'metrics': 'http://localhost:9094/metrics',
                'stats': 'http://localhost:8448/api/v1/stats'
            },
            'soar_integration': {
                'health': 'http://localhost:8449/health',
                'metrics': 'http://localhost:9095/metrics',
                'stats': 'http://localhost:8449/api/v1/stats'
            },
            'integration_orchestrator': {
                'health': 'http://localhost:8450/health',
                'metrics': 'http://localhost:9096/metrics',
                'stats': 'http://localhost:8450/api/v1/stats'
            }
        }
    
    async def start_monitoring(self):
        """Start performance monitoring"""
        self.logger.info("Starting NSM performance monitoring")
        self.running = True
        
        # Start monitoring tasks
        tasks = [
            asyncio.create_task(self._collect_system_metrics()),
            asyncio.create_task(self._collect_component_metrics()),
            asyncio.create_task(self._analyze_performance()),
            asyncio.create_task(self._publish_metrics()),
        ]
        
        try:
            # Wait for shutdown signal
            await self.shutdown_event.wait()
        finally:
            # Cancel all tasks
            for task in tasks:
                task.cancel()
            
            # Wait for tasks to complete
            await asyncio.gather(*tasks, return_exceptions=True)
            
            # Cleanup
            if self.database:
                self.database.close()
            
            if self.redis_client:
                self.redis_client.close()
            
            self.executor.shutdown(wait=True)
    
    async def _collect_system_metrics(self):
        """Collect system-level performance metrics"""
        while self.running:
            try:
                timestamp = datetime.utcnow()
                
                # CPU metrics
                cpu_percent = psutil.cpu_percent(interval=1)
                cpu_count = psutil.cpu_count()
                cpu_freq = psutil.cpu_freq()
                
                await self._store_metric(PerformanceMetric(
                    metric_id=f"system_cpu_{timestamp.timestamp()}",
                    component="system",
                    metric_name="cpu_usage_percent",
                    value=cpu_percent,
                    timestamp=timestamp,
                    unit="percent",
                    metadata={
                        'cpu_count': cpu_count,
                        'cpu_freq_current': cpu_freq.current if cpu_freq else None,
                        'cpu_freq_max': cpu_freq.max if cpu_freq else None
                    }
                ))
                
                # Memory metrics
                memory = psutil.virtual_memory()
                swap = psutil.swap_memory()
                
                await self._store_metric(PerformanceMetric(
                    metric_id=f"system_memory_{timestamp.timestamp()}",
                    component="system",
                    metric_name="memory_usage_percent",
                    value=memory.percent,
                    timestamp=timestamp,
                    unit="percent",
                    metadata={
                        'total_gb': memory.total / 1024 / 1024 / 1024,
                        'available_gb': memory.available / 1024 / 1024 / 1024,
                        'used_gb': memory.used / 1024 / 1024 / 1024,
                        'swap_percent': swap.percent,
                        'swap_total_gb': swap.total / 1024 / 1024 / 1024
                    }
                ))
                
                # Disk metrics
                disk_partitions = psutil.disk_partitions()
                for partition in disk_partitions:
                    try:
                        disk_usage = psutil.disk_usage(partition.mountpoint)
                        
                        await self._store_metric(PerformanceMetric(
                            metric_id=f"system_disk_{partition.device}_{timestamp.timestamp()}",
                            component="system",
                            metric_name="disk_usage_percent",
                            value=disk_usage.percent,
                            timestamp=timestamp,
                            unit="percent",
                            metadata={
                                'device': partition.device,
                                'mountpoint': partition.mountpoint,
                                'fstype': partition.fstype,
                                'total_gb': disk_usage.total / 1024 / 1024 / 1024,
                                'used_gb': disk_usage.used / 1024 / 1024 / 1024,
                                'free_gb': disk_usage.free / 1024 / 1024 / 1024
                            }
                        ))
                        
                        # Update Prometheus metrics
                        self.disk_usage.labels(component="system", mount=partition.mountpoint).set(disk_usage.percent)
                        
                    except PermissionError:
                        continue
                
                # Network metrics
                network_io = psutil.net_io_counters()
                if network_io:
                    await self._store_metric(PerformanceMetric(
                        metric_id=f"system_network_{timestamp.timestamp()}",
                        component="system",
                        metric_name="network_bytes_sent",
                        value=network_io.bytes_sent,
                        timestamp=timestamp,
                        unit="bytes",
                        metadata={
                            'bytes_recv': network_io.bytes_recv,
                            'packets_sent': network_io.packets_sent,
                            'packets_recv': network_io.packets_recv,
                            'errin': network_io.errin,
                            'errout': network_io.errout,
                            'dropin': network_io.dropin,
                            'dropout': network_io.dropout
                        }
                    ))
                    
                    # Update Prometheus metrics
                    self.network_io.labels(component="system", direction="sent").set(network_io.bytes_sent)
                    self.network_io.labels(component="system", direction="recv").set(network_io.bytes_recv)
                
                # Update Prometheus metrics
                self.cpu_usage.labels(component="system").set(cpu_percent)
                self.memory_usage.labels(component="system").set(memory.used)
                
                await asyncio.sleep(self.collection_interval)
                
            except Exception as e:
                self.logger.error(f"Error collecting system metrics: {e}")
                await asyncio.sleep(5)
    
    async def _collect_component_metrics(self):
        """Collect component-specific performance metrics"""
        while self.running:
            try:
                timestamp = datetime.utcnow()
                
                for component, endpoints in self.component_endpoints.items():
                    try:
                        # Collect health metrics
                        health_start = time.time()
                        health_response = requests.get(endpoints['health'], timeout=5)
                        health_duration = time.time() - health_start
                        
                        await self._store_metric(PerformanceMetric(
                            metric_id=f"{component}_health_{timestamp.timestamp()}",
                            component=component,
                            metric_name="health_check_duration",
                            value=health_duration * 1000,  # Convert to milliseconds
                            timestamp=timestamp,
                            unit="milliseconds",
                            metadata={
                                'status_code': health_response.status_code,
                                'healthy': health_response.status_code == 200
                            }
                        ))
                        
                        # Update Prometheus metrics
                        self.response_time.labels(component=component, endpoint="health").observe(health_duration)
                        
                        # Collect component stats if available
                        if 'stats' in endpoints:
                            try:
                                stats_response = requests.get(endpoints['stats'], timeout=5)
                                if stats_response.status_code == 200:
                                    stats_data = stats_response.json()
                                    
                                    # Extract key metrics from stats
                                    if 'events_processed' in stats_data:
                                        await self._store_metric(PerformanceMetric(
                                            metric_id=f"{component}_events_processed_{timestamp.timestamp()}",
                                            component=component,
                                            metric_name="events_processed_total",
                                            value=stats_data['events_processed'],
                                            timestamp=timestamp,
                                            unit="count"
                                        ))
                                    
                                    if 'processing_rate' in stats_data:
                                        self.event_processing_rate.labels(component=component).set(stats_data['processing_rate'])
                                    
                                    if 'queue_size' in stats_data:
                                        self.queue_size.labels(component=component, queue="main").set(stats_data['queue_size'])
                                    
                                    if 'error_rate' in stats_data:
                                        self.error_rate.labels(component=component).set(stats_data['error_rate'])
                                        
                            except Exception as e:
                                self.logger.debug(f"Could not collect stats for {component}: {e}")
                        
                        # Collect process-specific metrics for the component
                        await self._collect_process_metrics(component)
                        
                    except Exception as e:
                        self.logger.debug(f"Could not collect metrics for {component}: {e}")
                
                await asyncio.sleep(self.collection_interval)
                
            except Exception as e:
                self.logger.error(f"Error collecting component metrics: {e}")
                await asyncio.sleep(5)
    
    async def _collect_process_metrics(self, component: str):
        """Collect process-specific metrics for a component"""
        try:
            # Find processes by component name (simplified approach)
            component_processes = []
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    if component.replace('_', '-') in proc.info['name'] or \
                       any(component in cmd for cmd in proc.info['cmdline'] if cmd):
                        component_processes.append(proc)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            if component_processes:
                total_cpu = 0
                total_memory = 0
                
                for proc in component_processes:
                    try:
                        cpu_percent = proc.cpu_percent()
                        memory_info = proc.memory_info()
                        
                        total_cpu += cpu_percent
                        total_memory += memory_info.rss
                        
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                
                # Store aggregated metrics
                timestamp = datetime.utcnow()
                
                await self._store_metric(PerformanceMetric(
                    metric_id=f"{component}_process_cpu_{timestamp.timestamp()}",
                    component=component,
                    metric_name="process_cpu_percent",
                    value=total_cpu,
                    timestamp=timestamp,
                    unit="percent",
                    metadata={'process_count': len(component_processes)}
                ))
                
                await self._store_metric(PerformanceMetric(
                    metric_id=f"{component}_process_memory_{timestamp.timestamp()}",
                    component=component,
                    metric_name="process_memory_bytes",
                    value=total_memory,
                    timestamp=timestamp,
                    unit="bytes",
                    metadata={'process_count': len(component_processes)}
                ))
                
                # Update Prometheus metrics
                self.cpu_usage.labels(component=component).set(total_cpu)
                self.memory_usage.labels(component=component).set(total_memory)
                
        except Exception as e:
            self.logger.debug(f"Error collecting process metrics for {component}: {e}")
    
    async def _analyze_performance(self):
        """Analyze performance metrics and generate recommendations"""
        while self.running:
            try:
                await asyncio.sleep(self.analysis_interval)
                
                self.logger.info("Analyzing performance metrics...")
                
                # Analyze system metrics
                await self._analyze_system_performance()
                
                # Analyze component metrics
                for component in self.component_endpoints.keys():
                    await self._analyze_component_performance(component)
                
                # Generate optimization recommendations
                await self._generate_recommendations()
                
                self.logger.info(f"Performance analysis completed. Generated {len(self.recommendations)} recommendations.")
                
            except Exception as e:
                self.logger.error(f"Error analyzing performance: {e}")
                await asyncio.sleep(60)
    
    async def _analyze_system_performance(self):
        """Analyze system-level performance"""
        try:
            # Get recent system metrics
            recent_metrics = await self._get_recent_metrics("system", minutes=10)
            
            # Analyze CPU usage
            cpu_metrics = [m for m in recent_metrics if m.metric_name == "cpu_usage_percent"]
            if cpu_metrics:
                avg_cpu = sum(m.value for m in cpu_metrics) / len(cpu_metrics)
                max_cpu = max(m.value for m in cpu_metrics)
                
                if avg_cpu > self.thresholds.get('cpu_usage_high', 80):
                    await self._add_recommendation(
                        component="system",
                        category="cpu",
                        priority="high" if avg_cpu > 90 else "medium",
                        title="High CPU Usage Detected",
                        description=f"Average CPU usage is {avg_cpu:.1f}% (max: {max_cpu:.1f}%)",
                        impact="System performance degradation, increased response times",
                        implementation_effort="Low to Medium",
                        estimated_improvement="10-30% performance improvement",
                        commands=[
                            "top -bn1 | head -20",
                            "ps aux --sort=-%cpu | head -10",
                            "systemctl status nsm-*"
                        ]
                    )
            
            # Analyze memory usage
            memory_metrics = [m for m in recent_metrics if m.metric_name == "memory_usage_percent"]
            if memory_metrics:
                avg_memory = sum(m.value for m in memory_metrics) / len(memory_metrics)
                
                if avg_memory > self.thresholds.get('memory_usage_high', 85):
                    await self._add_recommendation(
                        component="system",
                        category="memory",
                        priority="high" if avg_memory > 95 else "medium",
                        title="High Memory Usage Detected",
                        description=f"Average memory usage is {avg_memory:.1f}%",
                        impact="Risk of OOM conditions, system instability",
                        implementation_effort="Medium",
                        estimated_improvement="Prevent system crashes, improve stability",
                        commands=[
                            "free -h",
                            "ps aux --sort=-%mem | head -10",
                            "systemctl restart nsm-memory-intensive-service"
                        ]
                    )
            
            # Analyze disk usage
            disk_metrics = [m for m in recent_metrics if m.metric_name == "disk_usage_percent"]
            for metric in disk_metrics:
                if metric.value > self.thresholds.get('disk_usage_high', 90):
                    mountpoint = metric.metadata.get('mountpoint', 'unknown')
                    await self._add_recommendation(
                        component="system",
                        category="disk",
                        priority="critical" if metric.value > 95 else "high",
                        title=f"High Disk Usage on {mountpoint}",
                        description=f"Disk usage is {metric.value:.1f}% on {mountpoint}",
                        impact="Risk of disk full, application failures",
                        implementation_effort="Low",
                        estimated_improvement="Prevent application failures",
                        commands=[
                            f"df -h {mountpoint}",
                            f"du -sh {mountpoint}/* | sort -rh | head -10",
                            f"find {mountpoint} -type f -size +100M -exec ls -lh {{}} \\;"
                        ]
                    )
                    
        except Exception as e:
            self.logger.error(f"Error analyzing system performance: {e}")
    
    async def _analyze_component_performance(self, component: str):
        """Analyze component-specific performance"""
        try:
            # Get recent component metrics
            recent_metrics = await self._get_recent_metrics(component, minutes=10)
            
            # Analyze response times
            health_metrics = [m for m in recent_metrics if m.metric_name == "health_check_duration"]
            if health_metrics:
                avg_response_time = sum(m.value for m in health_metrics) / len(health_metrics)
                max_response_time = max(m.value for m in health_metrics)
                
                threshold = self.thresholds.get('response_time_ms', 1000)
                if avg_response_time > threshold:
                    await self._add_recommendation(
                        component=component,
                        category="performance",
                        priority="medium" if avg_response_time < threshold * 2 else "high",
                        title=f"High Response Time for {component}",
                        description=f"Average response time is {avg_response_time:.1f}ms (max: {max_response_time:.1f}ms)",
                        impact="Degraded user experience, potential bottleneck",
                        implementation_effort="Medium",
                        estimated_improvement="20-50% response time improvement",
                        commands=[
                            f"systemctl status nsm-{component.replace('_', '-')}",
                            f"journalctl -u nsm-{component.replace('_', '-')} --since '10 minutes ago'",
                            f"curl -w '@curl-format.txt' -o /dev/null -s http://localhost:8450/health"
                        ]
                    )
            
            # Analyze CPU usage for component
            cpu_metrics = [m for m in recent_metrics if m.metric_name == "process_cpu_percent"]
            if cpu_metrics:
                avg_cpu = sum(m.value for m in cpu_metrics) / len(cpu_metrics)
                
                if avg_cpu > self.thresholds.get('component_cpu_high', 50):
                    await self._add_recommendation(
                        component=component,
                        category="cpu",
                        priority="medium",
                        title=f"High CPU Usage in {component}",
                        description=f"Component CPU usage is {avg_cpu:.1f}%",
                        impact="Component performance degradation",
                        implementation_effort="Medium",
                        estimated_improvement="10-25% CPU reduction",
                        commands=[
                            f"pgrep -f {component} | xargs -I {{}} ps -p {{}} -o pid,ppid,cmd,%cpu,%mem",
                            f"systemctl restart nsm-{component.replace('_', '-')}",
                            "echo 'Consider reviewing component configuration and tuning parameters'"
                        ]
                    )
            
            # Analyze memory usage for component
            memory_metrics = [m for m in recent_metrics if m.metric_name == "process_memory_bytes"]
            if memory_metrics:
                avg_memory_mb = sum(m.value for m in memory_metrics) / len(memory_metrics) / 1024 / 1024
                
                threshold_mb = self.thresholds.get('component_memory_mb', 1024)
                if avg_memory_mb > threshold_mb:
                    await self._add_recommendation(
                        component=component,
                        category="memory",
                        priority="medium" if avg_memory_mb < threshold_mb * 2 else "high",
                        title=f"High Memory Usage in {component}",
                        description=f"Component memory usage is {avg_memory_mb:.1f}MB",
                        impact="Memory pressure, potential memory leaks",
                        implementation_effort="Medium",
                        estimated_improvement="15-40% memory reduction",
                        commands=[
                            f"pgrep -f {component} | xargs -I {{}} ps -p {{}} -o pid,ppid,cmd,%cpu,%mem,vsz,rss",
                            f"systemctl restart nsm-{component.replace('_', '-')}",
                            "echo 'Consider implementing memory optimization and garbage collection tuning'"
                        ]
                    )
                    
        except Exception as e:
            self.logger.error(f"Error analyzing component {component} performance: {e}")
    
    async def _generate_recommendations(self):
        """Generate additional optimization recommendations based on analysis"""
        try:
            # Database optimization recommendations
            await self._analyze_database_performance()
            
            # Network optimization recommendations
            await self._analyze_network_performance()
            
            # Configuration optimization recommendations
            await self._analyze_configuration_optimization()
            
        except Exception as e:
            self.logger.error(f"Error generating recommendations: {e}")
    
    async def _analyze_database_performance(self):
        """Analyze database performance and generate recommendations"""
        try:
            # Check database file sizes
            db_files = [
                '/var/lib/nsm/signature_detection.db',
                '/var/lib/nsm/anomaly_detection.db',
                '/var/lib/nsm/asset_inventory.db',
                '/var/lib/nsm/vulnerability_correlation.db'
            ]
            
            for db_file in db_files:
                if Path(db_file).exists():
                    file_size_mb = Path(db_file).stat().st_size / 1024 / 1024
                    
                    if file_size_mb > self.thresholds.get('database_size_mb', 5000):
                        component = Path(db_file).stem
                        await self._add_recommendation(
                            component=component,
                            category="database",
                            priority="medium",
                            title=f"Large Database File: {component}",
                            description=f"Database file size is {file_size_mb:.1f}MB",
                            impact="Slower query performance, increased disk I/O",
                            implementation_effort="Low",
                            estimated_improvement="10-30% query performance improvement",
                            commands=[
                                f"sqlite3 {db_file} 'VACUUM;'",
                                f"sqlite3 {db_file} 'ANALYZE;'",
                                f"sqlite3 {db_file} 'PRAGMA optimize;'"
                            ]
                        )
                        
        except Exception as e:
            self.logger.error(f"Error analyzing database performance: {e}")
    
    async def _analyze_network_performance(self):
        """Analyze network performance and generate recommendations"""
        try:
            # Get recent network metrics
            recent_metrics = await self._get_recent_metrics("system", minutes=5)
            network_metrics = [m for m in recent_metrics if m.metric_name == "network_bytes_sent"]
            
            if network_metrics:
                # Calculate network throughput
                if len(network_metrics) >= 2:
                    first_metric = network_metrics[0]
                    last_metric = network_metrics[-1]
                    
                    time_diff = (last_metric.timestamp - first_metric.timestamp).total_seconds()
                    bytes_diff = last_metric.value - first_metric.value
                    
                    if time_diff > 0:
                        throughput_mbps = (bytes_diff * 8) / (time_diff * 1024 * 1024)
                        
                        # Check if throughput is unusually high
                        if throughput_mbps > self.thresholds.get('network_throughput_mbps', 1000):
                            await self._add_recommendation(
                                component="system",
                                category="network",
                                priority="medium",
                                title="High Network Throughput",
                                description=f"Network throughput is {throughput_mbps:.1f} Mbps",
                                impact="Potential network congestion, bandwidth limitations",
                                implementation_effort="Medium",
                                estimated_improvement="Optimize network utilization",
                                commands=[
                                    "iftop -t -s 60",
                                    "netstat -i",
                                    "ss -tuln"
                                ]
                            )
                            
        except Exception as e:
            self.logger.error(f"Error analyzing network performance: {e}")
    
    async def _analyze_configuration_optimization(self):
        """Analyze configuration for optimization opportunities"""
        try:
            # Check for common configuration optimizations
            config_files = [
                '/etc/nsm/signature-detection.yaml',
                '/etc/nsm/anomaly-detection.yaml',
                '/etc/nsm/integration-orchestrator.yaml'
            ]
            
            for config_file in config_files:
                if Path(config_file).exists():
                    try:
                        with open(config_file, 'r') as f:
                            config = yaml.safe_load(f)
                        
                        component = Path(config_file).stem
                        
                        # Check performance settings
                        perf_config = config.get('performance', {})
                        
                        # Check for suboptimal batch sizes
                        batch_size = perf_config.get('batch_size', 0)
                        if 0 < batch_size < 50:
                            await self._add_recommendation(
                                component=component,
                                category="configuration",
                                priority="low",
                                title=f"Small Batch Size in {component}",
                                description=f"Batch size is set to {batch_size}, consider increasing",
                                impact="Suboptimal throughput, increased overhead",
                                implementation_effort="Low",
                                estimated_improvement="10-20% throughput improvement",
                                commands=[
                                    f"sed -i 's/batch_size: {batch_size}/batch_size: 100/' {config_file}",
                                    f"systemctl restart nsm-{component.replace('_', '-')}"
                                ]
                            )
                        
                        # Check caching settings
                        caching = perf_config.get('caching', {})
                        if not caching.get('enabled', True):
                            await self._add_recommendation(
                                component=component,
                                category="configuration",
                                priority="medium",
                                title=f"Caching Disabled in {component}",
                                description="Caching is disabled, which may impact performance",
                                impact="Increased computation, slower response times",
                                implementation_effort="Low",
                                estimated_improvement="15-40% performance improvement",
                                commands=[
                                    f"yq e '.performance.caching.enabled = true' -i {config_file}",
                                    f"systemctl restart nsm-{component.replace('_', '-')}"
                                ]
                            )
                            
                    except Exception as e:
                        self.logger.debug(f"Could not analyze config file {config_file}: {e}")
                        
        except Exception as e:
            self.logger.error(f"Error analyzing configuration optimization: {e}")
    
    async def _store_metric(self, metric: PerformanceMetric):
        """Store performance metric in database and cache"""
        try:
            # Store in database
            cursor = self.database.cursor()
            cursor.execute('''
                INSERT INTO performance_metrics 
                (metric_id, component, metric_name, value, timestamp, unit, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                metric.metric_id,
                metric.component,
                metric.metric_name,
                metric.value,
                metric.timestamp,
                metric.unit,
                json.dumps(metric.metadata) if metric.metadata else None
            ))
            self.database.commit()
            
            # Store in memory cache
            cache_key = f"{metric.component}_{metric.metric_name}"
            self.metrics_history[cache_key].append(metric)
            self.current_metrics[cache_key] = metric
            
            # Store in Redis if available
            if self.redis_client:
                redis_key = f"nsm:metrics:{metric.component}:{metric.metric_name}"
                self.redis_client.zadd(redis_key, {json.dumps(asdict(metric)): metric.timestamp.timestamp()})
                self.redis_client.expire(redis_key, 86400)  # 24 hours
                
        except Exception as e:
            self.logger.error(f"Error storing metric: {e}")
    
    async def _get_recent_metrics(self, component: str, minutes: int = 10) -> List[PerformanceMetric]:
        """Get recent metrics for a component"""
        try:
            cutoff_time = datetime.utcnow() - timedelta(minutes=minutes)
            
            cursor = self.database.cursor()
            cursor.execute('''
                SELECT metric_id, component, metric_name, value, timestamp, unit, metadata
                FROM performance_metrics
                WHERE component = ? AND timestamp > ?
                ORDER BY timestamp DESC
            ''', (component, cutoff_time))
            
            metrics = []
            for row in cursor.fetchall():
                metadata = json.loads(row[6]) if row[6] else {}
                metric = PerformanceMetric(
                    metric_id=row[0],
                    component=row[1],
                    metric_name=row[2],
                    value=row[3],
                    timestamp=datetime.fromisoformat(row[4]),
                    unit=row[5],
                    metadata=metadata
                )
                metrics.append(metric)
            
            return metrics
            
        except Exception as e:
            self.logger.error(f"Error getting recent metrics: {e}")
            return []
    
    async def _add_recommendation(self, component: str, category: str, priority: str, 
                                title: str, description: str, impact: str, 
                                implementation_effort: str, estimated_improvement: str,
                                commands: List[str] = None):
        """Add optimization recommendation"""
        try:
            recommendation_id = f"{component}_{category}_{int(time.time())}"
            
            recommendation = OptimizationRecommendation(
                recommendation_id=recommendation_id,
                component=component,
                category=category,
                priority=priority,
                title=title,
                description=description,
                impact=impact,
                implementation_effort=implementation_effort,
                estimated_improvement=estimated_improvement,
                commands=commands or []
            )
            
            # Check if similar recommendation already exists
            existing = [r for r in self.recommendations 
                       if r.component == component and r.category == category and r.title == title]
            
            if not existing:
                self.recommendations.append(recommendation)
                
                # Store in database
                cursor = self.database.cursor()
                cursor.execute('''
                    INSERT OR IGNORE INTO optimization_recommendations
                    (recommendation_id, component, category, priority, title, description, 
                     impact, implementation_effort, estimated_improvement, commands)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    recommendation.recommendation_id,
                    recommendation.component,
                    recommendation.category,
                    recommendation.priority,
                    recommendation.title,
                    recommendation.description,
                    recommendation.impact,
                    recommendation.implementation_effort,
                    recommendation.estimated_improvement,
                    json.dumps(recommendation.commands)
                ))
                self.database.commit()
                
        except Exception as e:
            self.logger.error(f"Error adding recommendation: {e}")
    
    async def _publish_metrics(self):
        """Publish metrics to external systems"""
        while self.running:
            try:
                # Generate Prometheus metrics
                metrics_output = generate_latest(self.prometheus_registry).decode('utf-8')
                
                # Save to file for scraping
                metrics_file = Path("/var/lib/nsm/prometheus_metrics.txt")
                metrics_file.parent.mkdir(parents=True, exist_ok=True)
                metrics_file.write_text(metrics_output)
                
                # Publish to Redis if available
                if self.redis_client:
                    self.redis_client.set("nsm:prometheus_metrics", metrics_output, ex=300)  # 5 minutes
                
                await asyncio.sleep(30)  # Publish every 30 seconds
                
            except Exception as e:
                self.logger.error(f"Error publishing metrics: {e}")
                await asyncio.sleep(60)
    
    def get_current_metrics(self) -> Dict[str, Any]:
        """Get current performance metrics summary"""
        try:
            summary = {
                'timestamp': datetime.utcnow().isoformat(),
                'system_metrics': {},
                'component_metrics': {},
                'recommendations_count': len(self.recommendations),
                'recommendations': [asdict(r) for r in self.recommendations[:10]]  # Top 10
            }
            
            # System metrics
            for key, metric in self.current_metrics.items():
                if metric.component == 'system':
                    summary['system_metrics'][key] = {
                        'value': metric.value,
                        'unit': metric.unit,
                        'timestamp': metric.timestamp.isoformat()
                    }
                else:
                    if metric.component not in summary['component_metrics']:
                        summary['component_metrics'][metric.component] = {}
                    
                    summary['component_metrics'][metric.component][metric.metric_name] = {
                        'value': metric.value,
                        'unit': metric.unit,
                        'timestamp': metric.timestamp.isoformat()
                    }
            
            return summary
            
        except Exception as e:
            self.logger.error(f"Error getting current metrics: {e}")
            return {}
    
    def stop(self):
        """Stop performance monitoring"""
        self.logger.info("Stopping NSM performance monitoring")
        self.running = False
        self.shutdown_event.set()


async def main():
    """Main entry point"""
    import signal
    
    # Initialize optimizer
    optimizer = NSMPerformanceOptimizer()
    
    # Setup signal handlers
    def signal_handler(signum, frame):
        print(f"Received signal {signum}, shutting down...")
        optimizer.stop()
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Start monitoring
    await optimizer.start_monitoring()


if __name__ == "__main__":
    asyncio.run(main())