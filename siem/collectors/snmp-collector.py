#!/usr/bin/env python3
"""
iSECTECH SIEM SNMP Collector
High-performance SNMP monitoring for network devices and infrastructure components
"""

import asyncio
import json
import logging
import signal
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple, Any
from pathlib import Path
import yaml

# Third-party imports
import asyncpg
from kafka import KafkaProducer
from pysnmp.hlapi.asyncio import *
from prometheus_client import Counter, Histogram, Gauge, start_http_server
import redis
import structlog

# ═══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION AND DATA STRUCTURES
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class SNMPDevice:
    """SNMP device configuration"""
    hostname: str
    ip_address: str
    community: str = "public"
    version: str = "2c"
    port: int = 161
    timeout: int = 5
    retries: int = 3
    device_type: str = "generic"
    vendor: str = "unknown"
    model: str = "unknown"
    criticality: str = "medium"
    location: str = "unknown"
    contact: str = "unknown"
    polling_interval: int = 300  # 5 minutes
    enabled: bool = True
    security_monitoring: bool = True
    tags: List[str] = None

    def __post_init__(self):
        if self.tags is None:
            self.tags = []

@dataclass
class SNMPMetric:
    """SNMP metric definition"""
    name: str
    oid: str
    description: str
    metric_type: str = "gauge"  # gauge, counter, string
    unit: str = ""
    warning_threshold: Optional[float] = None
    critical_threshold: Optional[float] = None
    security_relevant: bool = False
    normalize_function: Optional[str] = None

@dataclass
class SNMPResult:
    """SNMP collection result"""
    device_hostname: str
    device_ip: str
    metric_name: str
    oid: str
    value: Any
    timestamp: datetime
    unit: str
    device_type: str
    vendor: str
    model: str
    criticality: str
    tags: List[str]
    warning_threshold: Optional[float] = None
    critical_threshold: Optional[float] = None
    security_relevant: bool = False
    collection_duration: float = 0.0
    error: Optional[str] = None

class SNMPCollectorConfig:
    """Configuration management for SNMP collector"""
    
    def __init__(self, config_file: str = "/etc/isectech-siem/snmp-collector.yaml"):
        self.config_file = Path(config_file)
        self.config = self._load_config()
        
    def _load_config(self) -> Dict:
        """Load configuration from YAML file"""
        try:
            with open(self.config_file, 'r') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            return self._default_config()
    
    def _default_config(self) -> Dict:
        """Default configuration"""
        return {
            "collector": {
                "worker_threads": 10,
                "batch_size": 100,
                "collection_timeout": 30,
                "retry_interval": 60,
                "metrics_port": 9161
            },
            "kafka": {
                "bootstrap_servers": ["kafka-1.isectech.local:9092"],
                "topic": "snmp-metrics",
                "batch_size": 1000,
                "linger_ms": 1000,
                "compression_type": "gzip"
            },
            "redis": {
                "host": "redis.isectech.local",
                "port": 6379,
                "db": 2,
                "password": None
            },
            "logging": {
                "level": "INFO",
                "format": "json"
            }
        }

# ═══════════════════════════════════════════════════════════════════════════════
# SNMP OID DEFINITIONS
# ═══════════════════════════════════════════════════════════════════════════════

# Standard SNMP OIDs for security monitoring
SECURITY_OIDS = {
    # System information
    "system_name": SNMPMetric("system_name", "1.3.6.1.2.1.1.5.0", "System name", "string"),
    "system_uptime": SNMPMetric("system_uptime", "1.3.6.1.2.1.1.3.0", "System uptime", "counter", "ticks"),
    "system_contact": SNMPMetric("system_contact", "1.3.6.1.2.1.1.4.0", "System contact", "string"),
    "system_location": SNMPMetric("system_location", "1.3.6.1.2.1.1.6.0", "System location", "string"),
    
    # Interface statistics
    "interface_admin_status": SNMPMetric("interface_admin_status", "1.3.6.1.2.1.2.2.1.7", "Interface admin status", "gauge"),
    "interface_oper_status": SNMPMetric("interface_oper_status", "1.3.6.1.2.1.2.2.1.8", "Interface operational status", "gauge"),
    "interface_in_octets": SNMPMetric("interface_in_octets", "1.3.6.1.2.1.2.2.1.10", "Interface input octets", "counter", "bytes"),
    "interface_out_octets": SNMPMetric("interface_out_octets", "1.3.6.1.2.1.2.2.1.16", "Interface output octets", "counter", "bytes"),
    "interface_in_errors": SNMPMetric("interface_in_errors", "1.3.6.1.2.1.2.2.1.14", "Interface input errors", "counter", security_relevant=True),
    "interface_out_errors": SNMPMetric("interface_out_errors", "1.3.6.1.2.1.2.2.1.20", "Interface output errors", "counter", security_relevant=True),
    
    # CPU and memory
    "cpu_utilization": SNMPMetric("cpu_utilization", "1.3.6.1.4.1.9.9.109.1.1.1.1.7", "CPU utilization", "gauge", "%", 80.0, 95.0),
    "memory_utilization": SNMPMetric("memory_utilization", "1.3.6.1.4.1.9.9.48.1.1.1.5", "Memory utilization", "gauge", "%", 80.0, 95.0),
    
    # Security-specific OIDs
    "failed_login_attempts": SNMPMetric("failed_login_attempts", "1.3.6.1.4.1.9.9.147.1.2.1.1.2", "Failed login attempts", "counter", security_relevant=True),
    "active_sessions": SNMPMetric("active_sessions", "1.3.6.1.4.1.9.9.147.1.1.1.1.4", "Active sessions", "gauge"),
    "temperature": SNMPMetric("temperature", "1.3.6.1.4.1.9.9.13.1.3.1.3", "Device temperature", "gauge", "celsius", 65.0, 80.0),
    
    # Firewall-specific OIDs (Cisco ASA)
    "firewall_connections": SNMPMetric("firewall_connections", "1.3.6.1.4.1.9.9.147.1.2.2.2.1.5", "Active firewall connections", "gauge"),
    "firewall_blocks": SNMPMetric("firewall_blocks", "1.3.6.1.4.1.9.9.147.1.2.1.1.12", "Firewall blocks", "counter", security_relevant=True),
    
    # Switch-specific OIDs
    "port_security_violations": SNMPMetric("port_security_violations", "1.3.6.1.4.1.9.9.315.1.2.1.1.9", "Port security violations", "counter", security_relevant=True),
    "spanning_tree_changes": SNMPMetric("spanning_tree_changes", "1.3.6.1.2.1.17.2.3.0", "Spanning tree topology changes", "counter", security_relevant=True),
}

# Vendor-specific OID mappings
VENDOR_OIDS = {
    "cisco": {
        **SECURITY_OIDS,
        "cisco_cpu": SNMPMetric("cisco_cpu", "1.3.6.1.4.1.9.9.109.1.1.1.1.7", "Cisco CPU utilization", "gauge", "%"),
        "cisco_memory": SNMPMetric("cisco_memory", "1.3.6.1.4.1.9.9.48.1.1.1.5", "Cisco memory utilization", "gauge", "%"),
    },
    "juniper": {
        **SECURITY_OIDS,
        "juniper_cpu": SNMPMetric("juniper_cpu", "1.3.6.1.4.1.2636.3.1.13.1.8", "Juniper CPU utilization", "gauge", "%"),
        "juniper_memory": SNMPMetric("juniper_memory", "1.3.6.1.4.1.2636.3.1.13.1.11", "Juniper memory utilization", "gauge", "%"),
    },
    "paloalto": {
        **SECURITY_OIDS,
        "panos_sessions": SNMPMetric("panos_sessions", "1.3.6.1.4.1.25461.2.1.2.1.9", "PAN-OS active sessions", "gauge"),
        "panos_threats": SNMPMetric("panos_threats", "1.3.6.1.4.1.25461.2.1.2.1.11", "PAN-OS threats detected", "counter", security_relevant=True),
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
# METRICS AND MONITORING
# ═══════════════════════════════════════════════════════════════════════════════

# Prometheus metrics
snmp_collections_total = Counter('snmp_collections_total', 'Total SNMP collections', ['device', 'status'])
snmp_collection_duration = Histogram('snmp_collection_duration_seconds', 'SNMP collection duration', ['device'])
snmp_errors_total = Counter('snmp_errors_total', 'Total SNMP errors', ['device', 'error_type'])
active_devices = Gauge('snmp_active_devices', 'Number of active SNMP devices')
security_alerts_total = Counter('snmp_security_alerts_total', 'Security alerts from SNMP', ['device', 'alert_type'])

# ═══════════════════════════════════════════════════════════════════════════════
# SNMP COLLECTOR CLASS
# ═══════════════════════════════════════════════════════════════════════════════

class SNMPCollector:
    """High-performance SNMP collector for security monitoring"""
    
    def __init__(self, config_file: str = "/etc/isectech-siem/snmp-collector.yaml"):
        self.config = SNMPCollectorConfig(config_file)
        self.logger = self._setup_logging()
        self.devices: Dict[str, SNMPDevice] = {}
        self.running = False
        self.tasks = []
        
        # Initialize components
        self.kafka_producer = None
        self.redis_client = None
        self.executor = ThreadPoolExecutor(max_workers=self.config.config["collector"]["worker_threads"])
        
    def _setup_logging(self) -> structlog.BoundLogger:
        """Setup structured logging"""
        logging.basicConfig(
            level=getattr(logging, self.config.config["logging"]["level"]),
            format="%(message)s"
        )
        
        structlog.configure(
            processors=[
                structlog.stdlib.filter_by_level,
                structlog.stdlib.add_logger_name,
                structlog.stdlib.add_log_level,
                structlog.stdlib.PositionalArgumentsFormatter(),
                structlog.processors.TimeStamper(fmt="iso"),
                structlog.processors.StackInfoRenderer(),
                structlog.processors.format_exc_info,
                structlog.processors.UnicodeDecoder(),
                structlog.processors.JSONRenderer()
            ],
            context_class=dict,
            logger_factory=structlog.stdlib.LoggerFactory(),
            wrapper_class=structlog.stdlib.BoundLogger,
            cache_logger_on_first_use=True,
        )
        
        return structlog.get_logger("snmp_collector")
    
    async def initialize(self):
        """Initialize collector components"""
        self.logger.info("Initializing SNMP collector")
        
        # Initialize Kafka producer
        self.kafka_producer = KafkaProducer(
            bootstrap_servers=self.config.config["kafka"]["bootstrap_servers"],
            value_serializer=lambda v: json.dumps(v).encode('utf-8'),
            batch_size=self.config.config["kafka"]["batch_size"],
            linger_ms=self.config.config["kafka"]["linger_ms"],
            compression_type=self.config.config["kafka"]["compression_type"]
        )
        
        # Initialize Redis client
        redis_config = self.config.config["redis"]
        self.redis_client = redis.Redis(
            host=redis_config["host"],
            port=redis_config["port"],
            db=redis_config["db"],
            password=redis_config.get("password"),
            decode_responses=True
        )
        
        # Load device configurations
        await self._load_devices()
        
        # Start Prometheus metrics server
        start_http_server(self.config.config["collector"]["metrics_port"])
        
        self.logger.info("SNMP collector initialized", devices_count=len(self.devices))
    
    async def _load_devices(self):
        """Load device configurations from database/config"""
        # In a real implementation, this would load from a database
        # For now, we'll use a sample configuration
        sample_devices = [
            SNMPDevice(
                hostname="core-switch-01.isectech.local",
                ip_address="10.0.1.10",
                community="isectech_readonly",
                device_type="switch",
                vendor="cisco",
                model="catalyst-9300",
                criticality="high",
                security_monitoring=True,
                tags=["core", "production", "network"]
            ),
            SNMPDevice(
                hostname="firewall-01.isectech.local", 
                ip_address="10.0.1.1",
                community="isectech_readonly",
                device_type="firewall",
                vendor="cisco",
                model="asa-5516",
                criticality="critical",
                security_monitoring=True,
                tags=["perimeter", "security", "production"]
            ),
            SNMPDevice(
                hostname="router-01.isectech.local",
                ip_address="10.0.1.5",
                community="isectech_readonly", 
                device_type="router",
                vendor="juniper",
                model="mx-series",
                criticality="high",
                security_monitoring=True,
                tags=["border", "production", "network"]
            )
        ]
        
        for device in sample_devices:
            self.devices[device.hostname] = device
    
    async def start(self):
        """Start the SNMP collector"""
        self.logger.info("Starting SNMP collector")
        self.running = True
        
        # Schedule collection tasks for each device
        for hostname, device in self.devices.items():
            if device.enabled:
                task = asyncio.create_task(self._device_collection_loop(device))
                self.tasks.append(task)
        
        # Start monitoring task
        self.tasks.append(asyncio.create_task(self._monitoring_loop()))
        
        # Wait for all tasks
        await asyncio.gather(*self.tasks, return_exceptions=True)
    
    async def stop(self):
        """Stop the SNMP collector"""
        self.logger.info("Stopping SNMP collector")
        self.running = False
        
        # Cancel all tasks
        for task in self.tasks:
            task.cancel()
        
        # Wait for tasks to complete
        await asyncio.gather(*self.tasks, return_exceptions=True)
        
        # Close connections
        if self.kafka_producer:
            self.kafka_producer.close()
        if self.redis_client:
            self.redis_client.close()
        
        self.executor.shutdown(wait=True)
    
    async def _device_collection_loop(self, device: SNMPDevice):
        """Main collection loop for a device"""
        logger = self.logger.bind(device=device.hostname)
        
        while self.running:
            try:
                start_time = time.time()
                
                # Collect metrics from device
                results = await self._collect_device_metrics(device)
                
                # Process and send results
                await self._process_results(results)
                
                collection_duration = time.time() - start_time
                snmp_collection_duration.labels(device=device.hostname).observe(collection_duration)
                snmp_collections_total.labels(device=device.hostname, status="success").inc()
                
                logger.debug("Collection completed", 
                           metrics_collected=len(results),
                           duration=collection_duration)
                
            except Exception as e:
                snmp_collections_total.labels(device=device.hostname, status="error").inc()
                snmp_errors_total.labels(device=device.hostname, error_type=type(e).__name__).inc()
                logger.error("Collection failed", error=str(e))
            
            # Wait for next collection interval
            await asyncio.sleep(device.polling_interval)
    
    async def _collect_device_metrics(self, device: SNMPDevice) -> List[SNMPResult]:
        """Collect SNMP metrics from a device"""
        results = []
        
        # Get OIDs to collect based on vendor
        oids_to_collect = VENDOR_OIDS.get(device.vendor, SECURITY_OIDS)
        
        # Collect metrics in batches
        batch_size = self.config.config["collector"]["batch_size"]
        oid_batches = [list(oids_to_collect.items())[i:i + batch_size] 
                      for i in range(0, len(oids_to_collect), batch_size)]
        
        for batch in oid_batches:
            batch_results = await self._collect_oid_batch(device, batch)
            results.extend(batch_results)
        
        return results
    
    async def _collect_oid_batch(self, device: SNMPDevice, oids: List[Tuple[str, SNMPMetric]]) -> List[SNMPResult]:
        """Collect a batch of OIDs from a device"""
        results = []
        
        try:
            # Prepare SNMP engine
            if device.version == "2c":
                auth_data = CommunityData(device.community)
            else:
                # For SNMPv3, would need more complex auth setup
                auth_data = CommunityData(device.community)
            
            transport_target = UdpTransportTarget((device.ip_address, device.port), 
                                                timeout=device.timeout, 
                                                retries=device.retries)
            
            # Collect each OID
            for metric_name, metric in oids:
                try:
                    start_time = time.time()
                    
                    # Perform SNMP GET
                    iterator = getCmd(
                        SnmpEngine(),
                        auth_data,
                        transport_target,
                        ContextData(),
                        ObjectType(ObjectIdentity(metric.oid))
                    )
                    
                    error_indication, error_status, error_index, var_binds = await iterator
                    collection_duration = time.time() - start_time
                    
                    if error_indication:
                        results.append(SNMPResult(
                            device_hostname=device.hostname,
                            device_ip=device.ip_address,
                            metric_name=metric_name,
                            oid=metric.oid,
                            value=None,
                            timestamp=datetime.now(timezone.utc),
                            unit=metric.unit,
                            device_type=device.device_type,
                            vendor=device.vendor,
                            model=device.model,
                            criticality=device.criticality,
                            tags=device.tags,
                            warning_threshold=metric.warning_threshold,
                            critical_threshold=metric.critical_threshold,
                            security_relevant=metric.security_relevant,
                            collection_duration=collection_duration,
                            error=str(error_indication)
                        ))
                        continue
                    
                    if error_status:
                        error_msg = f"{error_status.prettyPrint()} at {error_index and var_binds[int(error_index) - 1][0] or '?'}"
                        results.append(SNMPResult(
                            device_hostname=device.hostname,
                            device_ip=device.ip_address,
                            metric_name=metric_name,
                            oid=metric.oid,
                            value=None,
                            timestamp=datetime.now(timezone.utc),
                            unit=metric.unit,
                            device_type=device.device_type,
                            vendor=device.vendor,
                            model=device.model,
                            criticality=device.criticality,
                            tags=device.tags,
                            warning_threshold=metric.warning_threshold,
                            critical_threshold=metric.critical_threshold,
                            security_relevant=metric.security_relevant,
                            collection_duration=collection_duration,
                            error=error_msg
                        ))
                        continue
                    
                    # Extract value
                    for var_bind in var_binds:
                        value = var_bind[1]
                        if hasattr(value, 'prettyPrint'):
                            value = value.prettyPrint()
                        
                        # Convert value based on metric type
                        if metric.metric_type in ["gauge", "counter"] and isinstance(value, str):
                            try:
                                value = float(value)
                            except ValueError:
                                pass
                        
                        results.append(SNMPResult(
                            device_hostname=device.hostname,
                            device_ip=device.ip_address,
                            metric_name=metric_name,
                            oid=metric.oid,
                            value=value,
                            timestamp=datetime.now(timezone.utc),
                            unit=metric.unit,
                            device_type=device.device_type,
                            vendor=device.vendor,
                            model=device.model,
                            criticality=device.criticality,
                            tags=device.tags,
                            warning_threshold=metric.warning_threshold,
                            critical_threshold=metric.critical_threshold,
                            security_relevant=metric.security_relevant,
                            collection_duration=collection_duration
                        ))
                
                except Exception as e:
                    self.logger.error("Failed to collect metric", 
                                    device=device.hostname, 
                                    metric=metric_name, 
                                    error=str(e))
        
        except Exception as e:
            self.logger.error("Failed to collect batch", device=device.hostname, error=str(e))
        
        return results
    
    async def _process_results(self, results: List[SNMPResult]):
        """Process and send SNMP results"""
        for result in results:
            # Check for security alerts
            await self._check_security_alerts(result)
            
            # Cache result in Redis
            await self._cache_result(result)
            
            # Send to Kafka
            await self._send_to_kafka(result)
    
    async def _check_security_alerts(self, result: SNMPResult):
        """Check for security-related alerts"""
        if not result.security_relevant or result.error:
            return
        
        alert_triggered = False
        alert_type = ""
        
        # Check thresholds
        if isinstance(result.value, (int, float)):
            if result.critical_threshold and result.value >= result.critical_threshold:
                alert_type = "critical_threshold"
                alert_triggered = True
            elif result.warning_threshold and result.value >= result.warning_threshold:
                alert_type = "warning_threshold"
                alert_triggered = True
        
        # Check for security-specific conditions
        if result.metric_name == "failed_login_attempts" and isinstance(result.value, (int, float)) and result.value > 0:
            alert_type = "failed_logins"
            alert_triggered = True
        
        if result.metric_name == "port_security_violations" and isinstance(result.value, (int, float)) and result.value > 0:
            alert_type = "port_security"
            alert_triggered = True
        
        if result.metric_name == "firewall_blocks" and isinstance(result.value, (int, float)):
            # Check for unusual spike in blocks (would need baseline comparison)
            alert_type = "firewall_activity"
            # alert_triggered = True  # Would implement proper baseline logic
        
        if alert_triggered:
            security_alerts_total.labels(device=result.device_hostname, alert_type=alert_type).inc()
            
            # Create security alert
            alert = {
                "alert_id": f"snmp_{result.device_hostname}_{result.metric_name}_{int(time.time())}",
                "timestamp": result.timestamp.isoformat(),
                "device_hostname": result.device_hostname,
                "device_ip": result.device_ip,
                "alert_type": alert_type,
                "metric_name": result.metric_name,
                "value": result.value,
                "threshold": result.critical_threshold or result.warning_threshold,
                "severity": "critical" if result.critical_threshold and result.value >= result.critical_threshold else "warning",
                "device_type": result.device_type,
                "vendor": result.vendor,
                "criticality": result.criticality,
                "tags": result.tags,
                "raw_data": asdict(result)
            }
            
            # Send alert to high-priority topic
            self.kafka_producer.send("snmp-security-alerts", alert)
            
            self.logger.warning("Security alert triggered",
                              device=result.device_hostname,
                              metric=result.metric_name,
                              value=result.value,
                              alert_type=alert_type)
    
    async def _cache_result(self, result: SNMPResult):
        """Cache result in Redis for quick access"""
        try:
            cache_key = f"snmp:{result.device_hostname}:{result.metric_name}"
            cache_data = {
                "value": result.value,
                "timestamp": result.timestamp.isoformat(),
                "unit": result.unit,
                "error": result.error
            }
            
            # Store with TTL of 2x polling interval
            device = self.devices.get(result.device_hostname)
            ttl = (device.polling_interval * 2) if device else 600
            
            self.redis_client.setex(cache_key, ttl, json.dumps(cache_data))
            
        except Exception as e:
            self.logger.error("Failed to cache result", error=str(e))
    
    async def _send_to_kafka(self, result: SNMPResult):
        """Send result to Kafka"""
        try:
            # Convert result to dict for JSON serialization
            message = asdict(result)
            message["timestamp"] = result.timestamp.isoformat()
            
            # Send to Kafka
            self.kafka_producer.send(
                self.config.config["kafka"]["topic"],
                value=message,
                key=f"{result.device_hostname}:{result.metric_name}"
            )
            
        except Exception as e:
            self.logger.error("Failed to send to Kafka", error=str(e))
    
    async def _monitoring_loop(self):
        """Monitoring and health check loop"""
        while self.running:
            try:
                # Update active devices metric
                active_count = sum(1 for device in self.devices.values() if device.enabled)
                active_devices.set(active_count)
                
                # Perform health checks
                await self._health_check()
                
                # Log status
                self.logger.info("Health check completed", active_devices=active_count)
                
            except Exception as e:
                self.logger.error("Monitoring loop error", error=str(e))
            
            await asyncio.sleep(60)  # Health check every minute
    
    async def _health_check(self):
        """Perform health checks on collector components"""
        # Check Kafka connectivity
        try:
            self.kafka_producer.bootstrap_connected()
        except Exception as e:
            self.logger.error("Kafka health check failed", error=str(e))
        
        # Check Redis connectivity
        try:
            self.redis_client.ping()
        except Exception as e:
            self.logger.error("Redis health check failed", error=str(e))

# ═══════════════════════════════════════════════════════════════════════════════
# MAIN EXECUTION
# ═══════════════════════════════════════════════════════════════════════════════

async def main():
    """Main execution function"""
    collector = SNMPCollector()
    
    # Setup signal handling for graceful shutdown
    def signal_handler(signum, frame):
        print(f"\nReceived signal {signum}, shutting down...")
        asyncio.create_task(collector.stop())
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        await collector.initialize()
        await collector.start()
    except KeyboardInterrupt:
        print("Interrupted by user")
    except Exception as e:
        print(f"Collector error: {e}")
    finally:
        await collector.stop()

if __name__ == "__main__":
    asyncio.run(main())