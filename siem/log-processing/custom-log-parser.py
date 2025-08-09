#!/usr/bin/env python3
"""
iSECTECH SIEM Custom Log Parser
Advanced log parsing engine with custom format support and integrity verification
"""

import asyncio
import json
import logging
import hashlib
import hmac
import time
import re
import gzip
import base64
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Callable, Union
from pathlib import Path
import yaml

# Third-party imports
from kafka import KafkaProducer
from prometheus_client import Counter, Histogram, Gauge, start_http_server
import redis
import structlog
import jinja2

# ═══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION AND DATA STRUCTURES
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class LogFormat:
    """Custom log format definition"""
    name: str
    pattern: str
    pattern_type: str  # "regex", "grok", "json", "csv", "custom"
    field_mappings: Dict[str, str]
    timestamp_field: str
    timestamp_format: str
    severity_field: Optional[str] = None
    message_field: Optional[str] = None
    source_field: Optional[str] = None
    multiline_pattern: Optional[str] = None
    preprocessing_rules: List[str] = None
    validation_rules: List[str] = None
    enabled: bool = True
    priority: int = 100
    tags: List[str] = None

    def __post_init__(self):
        if self.preprocessing_rules is None:
            self.preprocessing_rules = []
        if self.validation_rules is None:
            self.validation_rules = []
        if self.tags is None:
            self.tags = []

@dataclass
class ParsedLog:
    """Parsed log event structure"""
    timestamp: datetime
    raw_message: str
    parsed_fields: Dict[str, Any]
    format_name: str
    source_system: str
    severity: str
    message: str
    log_hash: str
    integrity_verified: bool
    parsing_errors: List[str] = None
    
    # Enrichment fields
    geoip_data: Dict[str, Any] = None
    threat_intel: Dict[str, Any] = None
    asset_data: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.parsing_errors is None:
            self.parsing_errors = []
        if self.geoip_data is None:
            self.geoip_data = {}
        if self.threat_intel is None:
            self.threat_intel = {}
        if self.asset_data is None:
            self.asset_data = {}

@dataclass
class IntegrityConfig:
    """Log integrity verification configuration"""
    enabled: bool = True
    hash_algorithm: str = "sha256"
    hmac_key: Optional[str] = None
    signature_field: Optional[str] = None
    verify_chain: bool = False
    chain_field: Optional[str] = None
    allow_unsigned: bool = True
    require_timestamp_validation: bool = True
    max_timestamp_drift: int = 300  # seconds

class CustomLogParserConfig:
    """Configuration management for custom log parser"""
    
    def __init__(self, config_file: str = "/etc/isectech-siem/log-parser.yaml"):
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
            "parser": {
                "worker_threads": 20,
                "batch_size": 1000,
                "processing_timeout": 30,
                "max_line_length": 1048576,  # 1MB
                "metrics_port": 9167
            },
            "kafka": {
                "bootstrap_servers": ["kafka-1.isectech.local:9092"],
                "input_topic": "raw-logs",
                "output_topic": "parsed-logs",
                "error_topic": "parsing-errors",
                "batch_size": 1000,
                "linger_ms": 1000,
                "compression_type": "gzip"
            },
            "redis": {
                "host": "redis.isectech.local",
                "port": 6379,
                "db": 7,
                "password": None
            },
            "integrity": {
                "enabled": True,
                "hash_algorithm": "sha256",
                "verify_chain": False,
                "allow_unsigned": True,
                "require_timestamp_validation": True,
                "max_timestamp_drift": 300
            },
            "logging": {
                "level": "INFO",
                "format": "json"
            }
        }

# ═══════════════════════════════════════════════════════════════════════════════
# PREDEFINED LOG FORMATS
# ═══════════════════════════════════════════════════════════════════════════════

BUILTIN_FORMATS = {
    "apache_common": LogFormat(
        name="apache_common",
        pattern=r'^(?P<client_ip>\S+) \S+ (?P<user>\S+) \[(?P<timestamp>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+) (?P<protocol>\S+)" (?P<status>\d+) (?P<size>\S+)$',
        pattern_type="regex",
        field_mappings={
            "client_ip": "source.ip",
            "user": "user.name",
            "method": "http.method",
            "path": "url.path",
            "protocol": "http.version",
            "status": "http.response.status_code",
            "size": "http.response.body.bytes"
        },
        timestamp_field="timestamp",
        timestamp_format="%d/%b/%Y:%H:%M:%S %z",
        severity_field="status",
        message_field="path",
        source_field="client_ip",
        tags=["apache", "web", "access"]
    ),
    
    "nginx_json": LogFormat(
        name="nginx_json",
        pattern="",
        pattern_type="json",
        field_mappings={
            "remote_addr": "source.ip",
            "remote_user": "user.name",
            "request": "http.request.line",
            "status": "http.response.status_code",
            "body_bytes_sent": "http.response.body.bytes",
            "http_referer": "http.request.referrer",
            "http_user_agent": "user_agent.original"
        },
        timestamp_field="time_iso8601",
        timestamp_format="iso8601",
        severity_field="status",
        message_field="request",
        source_field="remote_addr",
        tags=["nginx", "web", "access", "json"]
    ),
    
    "windows_eventlog": LogFormat(
        name="windows_eventlog",
        pattern=r'^(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (?P<level>\w+) (?P<source>\w+) (?P<event_id>\d+) (?P<message>.*)$',
        pattern_type="regex",
        field_mappings={
            "level": "log.level",
            "source": "winlog.provider_name",
            "event_id": "winlog.event_id",
            "message": "message"
        },
        timestamp_field="timestamp",
        timestamp_format="%Y-%m-%d %H:%M:%S",
        severity_field="level",
        message_field="message",
        tags=["windows", "eventlog", "system"]
    ),
    
    "syslog_rfc3164": LogFormat(
        name="syslog_rfc3164",
        pattern=r'^<(?P<priority>\d+)>(?P<timestamp>\w{3} +\d{1,2} \d{2}:\d{2}:\d{2}) (?P<hostname>\S+) (?P<tag>[^:]+): (?P<message>.*)$',
        pattern_type="regex",
        field_mappings={
            "priority": "log.syslog.priority",
            "hostname": "host.hostname",
            "tag": "process.name",
            "message": "message"
        },
        timestamp_field="timestamp",
        timestamp_format="%b %d %H:%M:%S",
        severity_field="priority",
        message_field="message",
        source_field="hostname",
        tags=["syslog", "rfc3164", "system"]
    ),
    
    "fortinet_fortigate": LogFormat(
        name="fortinet_fortigate",
        pattern=r'(?P<key_value_pairs>(?:\w+=[^=]* )*)',
        pattern_type="custom",
        field_mappings={
            "srcip": "source.ip",
            "dstip": "destination.ip",
            "srcport": "source.port",
            "dstport": "destination.port",
            "action": "event.action",
            "policyid": "rule.id",
            "service": "network.protocol"
        },
        timestamp_field="date",
        timestamp_format="%Y-%m-%d",
        severity_field="level",
        message_field="msg",
        source_field="srcip",
        tags=["fortinet", "fortigate", "firewall", "security"]
    ),
    
    "checkpoint_logs": LogFormat(
        name="checkpoint_logs",
        pattern=r'^(?P<timestamp>\d+ \w{3} \d{4} \d{2}:\d{2}:\d{2}) (?P<hostname>\S+) (?P<product>\S+): (?P<fields>.*)$',
        pattern_type="custom",
        field_mappings={
            "src": "source.ip",
            "dst": "destination.ip",
            "service": "destination.port",
            "action": "event.action",
            "rule": "rule.name",
            "product": "observer.product"
        },
        timestamp_field="timestamp",
        timestamp_format="%d %b %Y %H:%M:%S",
        severity_field="action",
        message_field="fields",
        source_field="src",
        tags=["checkpoint", "firewall", "security"]
    ),
    
    "json_generic": LogFormat(
        name="json_generic",
        pattern="",
        pattern_type="json",
        field_mappings={
            "@timestamp": "timestamp",
            "level": "log.level",
            "message": "message",
            "logger": "log.logger",
            "host": "host.name",
            "source_ip": "source.ip"
        },
        timestamp_field="@timestamp",
        timestamp_format="iso8601",
        severity_field="level",
        message_field="message",
        source_field="host",
        tags=["json", "generic", "structured"]
    ),
    
    "csv_custom": LogFormat(
        name="csv_custom",
        pattern="",
        pattern_type="csv",
        field_mappings={
            "0": "timestamp",
            "1": "source.ip",
            "2": "event.action",
            "3": "user.name",
            "4": "message"
        },
        timestamp_field="0",
        timestamp_format="%Y-%m-%d %H:%M:%S",
        severity_field="2",
        message_field="4",
        source_field="1",
        tags=["csv", "custom", "structured"]
    )
}

# ═══════════════════════════════════════════════════════════════════════════════
# METRICS AND MONITORING
# ═══════════════════════════════════════════════════════════════════════════════

# Prometheus metrics
logs_parsed_total = Counter('logs_parsed_total', 'Total logs parsed', ['format', 'status'])
parsing_duration = Histogram('log_parsing_duration_seconds', 'Log parsing duration', ['format'])
parsing_errors_total = Counter('log_parsing_errors_total', 'Total parsing errors', ['format', 'error_type'])
integrity_checks_total = Counter('log_integrity_checks_total', 'Total integrity checks', ['status'])
custom_formats_loaded = Gauge('custom_log_formats_loaded', 'Number of custom log formats loaded')

# ═══════════════════════════════════════════════════════════════════════════════
# CUSTOM LOG PARSER CLASS
# ═══════════════════════════════════════════════════════════════════════════════

class CustomLogParser:
    """Advanced custom log parser with integrity verification"""
    
    def __init__(self, config_file: str = "/etc/isectech-siem/log-parser.yaml"):
        self.config = CustomLogParserConfig(config_file)
        self.logger = self._setup_logging()
        self.formats: Dict[str, LogFormat] = {}
        self.compiled_patterns: Dict[str, re.Pattern] = {}
        self.jinja_env = jinja2.Environment()
        self.running = False
        self.tasks = []
        
        # Initialize components
        self.kafka_producer = None
        self.redis_client = None
        self.executor = ThreadPoolExecutor(max_workers=self.config.config["parser"]["worker_threads"])
        
        # Integrity configuration
        self.integrity_config = IntegrityConfig(**self.config.config.get("integrity", {}))
        
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
        
        return structlog.get_logger("custom_log_parser")
    
    async def initialize(self):
        """Initialize parser components"""
        self.logger.info("Initializing Custom Log Parser")
        
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
        
        # Load log formats
        await self._load_log_formats()
        
        # Start Prometheus metrics server
        start_http_server(self.config.config["parser"]["metrics_port"])
        
        self.logger.info("Custom Log Parser initialized", formats_count=len(self.formats))
    
    async def _load_log_formats(self):
        """Load log formats from configuration and builtin definitions"""
        # Load builtin formats
        for name, log_format in BUILTIN_FORMATS.items():
            self.formats[name] = log_format
            if log_format.pattern and log_format.pattern_type == "regex":
                try:
                    self.compiled_patterns[name] = re.compile(log_format.pattern, re.MULTILINE if log_format.multiline_pattern else 0)
                except re.error as e:
                    self.logger.error("Failed to compile regex pattern", format=name, error=str(e))
        
        # Load custom formats from configuration files
        custom_formats_dir = Path("/etc/isectech-siem/custom-formats")
        if custom_formats_dir.exists():
            for format_file in custom_formats_dir.glob("*.yaml"):
                try:
                    with open(format_file, 'r') as f:
                        format_config = yaml.safe_load(f)
                    
                    log_format = LogFormat(**format_config)
                    self.formats[log_format.name] = log_format
                    
                    if log_format.pattern and log_format.pattern_type == "regex":
                        self.compiled_patterns[log_format.name] = re.compile(
                            log_format.pattern, 
                            re.MULTILINE if log_format.multiline_pattern else 0
                        )
                    
                    self.logger.info("Loaded custom format", format=log_format.name, file=format_file.name)
                    
                except Exception as e:
                    self.logger.error("Failed to load custom format", file=format_file.name, error=str(e))
        
        # Update metrics
        custom_formats_loaded.set(len(self.formats))
        
        # Sort formats by priority
        self.formats = dict(sorted(self.formats.items(), key=lambda x: x[1].priority))
    
    async def start(self):
        """Start the parser"""
        self.logger.info("Starting Custom Log Parser")
        self.running = True
        
        # Start processing tasks
        for i in range(self.config.config["parser"]["worker_threads"]):
            task = asyncio.create_task(self._processing_loop(f"worker-{i}"))
            self.tasks.append(task)
        
        # Start monitoring task
        self.tasks.append(asyncio.create_task(self._monitoring_loop()))
        
        # Wait for all tasks
        await asyncio.gather(*self.tasks, return_exceptions=True)
    
    async def stop(self):
        """Stop the parser"""
        self.logger.info("Stopping Custom Log Parser")
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
    
    async def _processing_loop(self, worker_id: str):
        """Main processing loop for parsing logs"""
        logger = self.logger.bind(worker=worker_id)
        
        while self.running:
            try:
                # Get batch of raw logs from Kafka (stub - would use actual Kafka consumer)
                raw_logs = await self._get_raw_logs_batch()
                
                if not raw_logs:
                    await asyncio.sleep(1)
                    continue
                
                # Process batch
                for raw_log in raw_logs:
                    start_time = time.time()
                    
                    try:
                        parsed_log = await self._parse_log(raw_log)
                        
                        if parsed_log:
                            # Verify integrity if enabled
                            if self.integrity_config.enabled:
                                await self._verify_log_integrity(parsed_log)
                            
                            # Send to output topic
                            await self._send_parsed_log(parsed_log)
                            
                            # Update metrics
                            parsing_duration.labels(format=parsed_log.format_name).observe(time.time() - start_time)
                            logs_parsed_total.labels(format=parsed_log.format_name, status="success").inc()
                        else:
                            logs_parsed_total.labels(format="unknown", status="failed").inc()
                            await self._send_parsing_error(raw_log, "No matching format found")
                    
                    except Exception as e:
                        parsing_errors_total.labels(format="unknown", error_type=type(e).__name__).inc()
                        logger.error("Failed to parse log", error=str(e), raw_log=raw_log[:200])
                        await self._send_parsing_error(raw_log, str(e))
                
            except Exception as e:
                logger.error("Processing loop error", error=str(e))
                await asyncio.sleep(5)
    
    async def _get_raw_logs_batch(self) -> List[str]:
        """Get batch of raw logs (stub - would implement Kafka consumer)"""
        # This is a placeholder - in production would use Kafka consumer
        return []
    
    async def _parse_log(self, raw_log: str) -> Optional[ParsedLog]:
        """Parse a raw log entry using available formats"""
        # Preprocess log
        raw_log = raw_log.strip()
        if not raw_log or len(raw_log) > self.config.config["parser"]["max_line_length"]:
            return None
        
        # Try each format in priority order
        for format_name, log_format in self.formats.items():
            if not log_format.enabled:
                continue
            
            try:
                parsed_fields = None
                
                if log_format.pattern_type == "regex":
                    parsed_fields = await self._parse_regex(raw_log, log_format, format_name)
                elif log_format.pattern_type == "json":
                    parsed_fields = await self._parse_json(raw_log, log_format)
                elif log_format.pattern_type == "csv":
                    parsed_fields = await self._parse_csv(raw_log, log_format)
                elif log_format.pattern_type == "custom":
                    parsed_fields = await self._parse_custom(raw_log, log_format)
                
                if parsed_fields:
                    # Apply field mappings
                    mapped_fields = self._apply_field_mappings(parsed_fields, log_format)
                    
                    # Extract timestamp
                    timestamp = self._extract_timestamp(mapped_fields, log_format)
                    
                    # Create parsed log object
                    parsed_log = ParsedLog(
                        timestamp=timestamp,
                        raw_message=raw_log,
                        parsed_fields=mapped_fields,
                        format_name=format_name,
                        source_system=mapped_fields.get("host.name", "unknown"),
                        severity=self._extract_severity(mapped_fields, log_format),
                        message=self._extract_message(mapped_fields, log_format),
                        log_hash=self._calculate_log_hash(raw_log),
                        integrity_verified=False
                    )
                    
                    return parsed_log
                
            except Exception as e:
                parsing_errors_total.labels(format=format_name, error_type=type(e).__name__).inc()
                self.logger.debug("Format parsing failed", format=format_name, error=str(e))
                continue
        
        return None
    
    async def _parse_regex(self, raw_log: str, log_format: LogFormat, format_name: str) -> Optional[Dict[str, Any]]:
        """Parse log using regex pattern"""
        pattern = self.compiled_patterns.get(format_name)
        if not pattern:
            return None
        
        match = pattern.match(raw_log)
        if match:
            return match.groupdict()
        
        return None
    
    async def _parse_json(self, raw_log: str, log_format: LogFormat) -> Optional[Dict[str, Any]]:
        """Parse JSON log format"""
        try:
            return json.loads(raw_log)
        except json.JSONDecodeError:
            return None
    
    async def _parse_csv(self, raw_log: str, log_format: LogFormat) -> Optional[Dict[str, Any]]:
        """Parse CSV log format"""
        try:
            import csv
            import io
            
            # Use CSV reader to parse
            reader = csv.reader(io.StringIO(raw_log))
            row = next(reader)
            
            # Create field mapping based on position
            fields = {}
            for i, value in enumerate(row):
                fields[str(i)] = value
            
            return fields
        except:
            return None
    
    async def _parse_custom(self, raw_log: str, log_format: LogFormat) -> Optional[Dict[str, Any]]:
        """Parse custom log format (key-value pairs, etc.)"""
        if log_format.name == "fortinet_fortigate":
            return self._parse_fortinet_kv(raw_log)
        elif log_format.name == "checkpoint_logs":
            return self._parse_checkpoint_log(raw_log)
        
        return None
    
    def _parse_fortinet_kv(self, raw_log: str) -> Dict[str, Any]:
        """Parse Fortinet key-value format"""
        fields = {}
        
        # Extract key-value pairs
        kv_pattern = r'(\w+)=([^=]*?)(?=\s+\w+=|\s*$)'
        matches = re.findall(kv_pattern, raw_log)
        
        for key, value in matches:
            fields[key] = value.strip('"')
        
        return fields
    
    def _parse_checkpoint_log(self, raw_log: str) -> Dict[str, Any]:
        """Parse Check Point log format"""
        fields = {}
        
        # Extract pipe-separated fields
        parts = raw_log.split('|')
        for part in parts:
            if '=' in part:
                key, value = part.split('=', 1)
                fields[key.strip()] = value.strip()
        
        return fields
    
    def _apply_field_mappings(self, parsed_fields: Dict[str, Any], log_format: LogFormat) -> Dict[str, Any]:
        """Apply field mappings to normalize field names"""
        mapped_fields = {}
        
        for source_field, target_field in log_format.field_mappings.items():
            if source_field in parsed_fields:
                mapped_fields[target_field] = parsed_fields[source_field]
        
        # Copy unmapped fields
        for field, value in parsed_fields.items():
            if field not in log_format.field_mappings:
                mapped_fields[field] = value
        
        return mapped_fields
    
    def _extract_timestamp(self, fields: Dict[str, Any], log_format: LogFormat) -> datetime:
        """Extract and parse timestamp from log fields"""
        timestamp_value = fields.get(log_format.timestamp_field)
        if not timestamp_value:
            return datetime.now(timezone.utc)
        
        try:
            if log_format.timestamp_format == "iso8601":
                # Handle ISO 8601 format
                if isinstance(timestamp_value, str):
                    # Clean up timestamp string
                    timestamp_value = timestamp_value.replace('Z', '+00:00')
                    return datetime.fromisoformat(timestamp_value)
                else:
                    return timestamp_value
            elif log_format.timestamp_format == "epoch":
                # Handle epoch timestamp
                return datetime.fromtimestamp(float(timestamp_value), timezone.utc)
            else:
                # Handle custom format
                return datetime.strptime(str(timestamp_value), log_format.timestamp_format).replace(tzinfo=timezone.utc)
        
        except (ValueError, TypeError) as e:
            self.logger.debug("Failed to parse timestamp", timestamp=timestamp_value, format=log_format.timestamp_format, error=str(e))
            return datetime.now(timezone.utc)
    
    def _extract_severity(self, fields: Dict[str, Any], log_format: LogFormat) -> str:
        """Extract severity level from log fields"""
        if log_format.severity_field and log_format.severity_field in fields:
            severity = str(fields[log_format.severity_field])
            
            # Normalize severity levels
            severity_lower = severity.lower()
            if severity_lower in ["error", "err", "critical", "crit", "fatal", "emergency", "emerg"]:
                return "error"
            elif severity_lower in ["warning", "warn", "alert"]:
                return "warning"
            elif severity_lower in ["info", "information", "notice"]:
                return "info"
            elif severity_lower in ["debug", "trace"]:
                return "debug"
            
            # HTTP status code mapping
            if severity.isdigit():
                status = int(severity)
                if status >= 500:
                    return "error"
                elif status >= 400:
                    return "warning"
                else:
                    return "info"
        
        return "info"
    
    def _extract_message(self, fields: Dict[str, Any], log_format: LogFormat) -> str:
        """Extract main message from log fields"""
        if log_format.message_field and log_format.message_field in fields:
            return str(fields[log_format.message_field])
        
        # Fallback to common message fields
        for field in ["message", "msg", "description", "event", "request", "path"]:
            if field in fields:
                return str(fields[field])
        
        return ""
    
    def _calculate_log_hash(self, raw_log: str) -> str:
        """Calculate hash of raw log for integrity verification"""
        hash_algo = getattr(hashlib, self.integrity_config.hash_algorithm)
        return hash_algo(raw_log.encode('utf-8')).hexdigest()
    
    async def _verify_log_integrity(self, parsed_log: ParsedLog):
        """Verify log integrity using configured method"""
        integrity_verified = True
        
        try:
            if self.integrity_config.hmac_key and self.integrity_config.signature_field:
                # HMAC signature verification
                expected_signature = parsed_log.parsed_fields.get(self.integrity_config.signature_field)
                if expected_signature:
                    calculated_signature = hmac.new(
                        self.integrity_config.hmac_key.encode('utf-8'),
                        parsed_log.raw_message.encode('utf-8'),
                        getattr(hashlib, self.integrity_config.hash_algorithm)
                    ).hexdigest()
                    
                    integrity_verified = hmac.compare_digest(expected_signature, calculated_signature)
                else:
                    integrity_verified = self.integrity_config.allow_unsigned
            
            # Timestamp validation
            if self.integrity_config.require_timestamp_validation:
                time_diff = abs((datetime.now(timezone.utc) - parsed_log.timestamp).total_seconds())
                if time_diff > self.integrity_config.max_timestamp_drift:
                    integrity_verified = False
                    parsed_log.parsing_errors.append(f"Timestamp drift too large: {time_diff}s")
            
            # Chain verification (if enabled)
            if self.integrity_config.verify_chain and self.integrity_config.chain_field:
                # Implement chain verification logic here
                pass
            
            parsed_log.integrity_verified = integrity_verified
            integrity_checks_total.labels(status="verified" if integrity_verified else "failed").inc()
            
        except Exception as e:
            self.logger.error("Integrity verification failed", error=str(e))
            parsed_log.integrity_verified = False
            parsed_log.parsing_errors.append(f"Integrity verification error: {str(e)}")
            integrity_checks_total.labels(status="error").inc()
    
    async def _send_parsed_log(self, parsed_log: ParsedLog):
        """Send parsed log to output topic"""
        try:
            message = asdict(parsed_log)
            message["timestamp"] = parsed_log.timestamp.isoformat()
            
            self.kafka_producer.send(
                self.config.config["kafka"]["output_topic"],
                value=message,
                key=parsed_log.log_hash
            )
            
        except Exception as e:
            self.logger.error("Failed to send parsed log", error=str(e))
    
    async def _send_parsing_error(self, raw_log: str, error_message: str):
        """Send parsing error to error topic"""
        try:
            error_event = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "raw_log": raw_log,
                "error_message": error_message,
                "parser_version": "1.0.0"
            }
            
            self.kafka_producer.send(
                self.config.config["kafka"]["error_topic"],
                value=error_event
            )
            
        except Exception as e:
            self.logger.error("Failed to send parsing error", error=str(e))
    
    async def _monitoring_loop(self):
        """Monitoring and health check loop"""
        while self.running:
            try:
                # Perform health checks
                await self._health_check()
                
                self.logger.info("Health check completed", formats_loaded=len(self.formats))
                
            except Exception as e:
                self.logger.error("Monitoring loop error", error=str(e))
            
            await asyncio.sleep(60)  # Health check every minute
    
    async def _health_check(self):
        """Perform health checks on parser components"""
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
    # PUBLIC API METHODS
    # ═══════════════════════════════════════════════════════════════════════════════
    
    async def parse_single_log(self, raw_log: str, format_hint: Optional[str] = None) -> Optional[ParsedLog]:
        """Parse a single log entry (for testing/API use)"""
        if format_hint and format_hint in self.formats:
            # Try specific format first
            log_format = self.formats[format_hint]
            try:
                if log_format.pattern_type == "regex":
                    parsed_fields = await self._parse_regex(raw_log, log_format, format_hint)
                elif log_format.pattern_type == "json":
                    parsed_fields = await self._parse_json(raw_log, log_format)
                elif log_format.pattern_type == "csv":
                    parsed_fields = await self._parse_csv(raw_log, log_format)
                elif log_format.pattern_type == "custom":
                    parsed_fields = await self._parse_custom(raw_log, log_format)
                
                if parsed_fields:
                    mapped_fields = self._apply_field_mappings(parsed_fields, log_format)
                    timestamp = self._extract_timestamp(mapped_fields, log_format)
                    
                    return ParsedLog(
                        timestamp=timestamp,
                        raw_message=raw_log,
                        parsed_fields=mapped_fields,
                        format_name=format_hint,
                        source_system=mapped_fields.get("host.name", "unknown"),
                        severity=self._extract_severity(mapped_fields, log_format),
                        message=self._extract_message(mapped_fields, log_format),
                        log_hash=self._calculate_log_hash(raw_log),
                        integrity_verified=False
                    )
            except Exception as e:
                self.logger.debug("Specific format parsing failed", format=format_hint, error=str(e))
        
        # Fall back to general parsing
        return await self._parse_log(raw_log)
    
    def add_custom_format(self, log_format: LogFormat):
        """Add a custom log format at runtime"""
        self.formats[log_format.name] = log_format
        
        if log_format.pattern and log_format.pattern_type == "regex":
            try:
                self.compiled_patterns[log_format.name] = re.compile(
                    log_format.pattern,
                    re.MULTILINE if log_format.multiline_pattern else 0
                )
            except re.error as e:
                self.logger.error("Failed to compile custom format regex", format=log_format.name, error=str(e))
                return False
        
        # Resort formats by priority
        self.formats = dict(sorted(self.formats.items(), key=lambda x: x[1].priority))
        custom_formats_loaded.set(len(self.formats))
        
        self.logger.info("Added custom format", format=log_format.name)
        return True
    
    def remove_custom_format(self, format_name: str) -> bool:
        """Remove a custom log format"""
        if format_name in self.formats:
            del self.formats[format_name]
            if format_name in self.compiled_patterns:
                del self.compiled_patterns[format_name]
            
            custom_formats_loaded.set(len(self.formats))
            self.logger.info("Removed custom format", format=format_name)
            return True
        
        return False
    
    def get_supported_formats(self) -> List[str]:
        """Get list of supported log formats"""
        return list(self.formats.keys())

# ═══════════════════════════════════════════════════════════════════════════════
# MAIN EXECUTION
# ═══════════════════════════════════════════════════════════════════════════════

async def main():
    """Main execution function"""
    parser = CustomLogParser()
    
    # Setup signal handling for graceful shutdown
    def signal_handler(signum, frame):
        print(f"\nReceived signal {signum}, shutting down...")
        asyncio.create_task(parser.stop())
    
    import signal
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        await parser.initialize()
        await parser.start()
    except KeyboardInterrupt:
        print("Interrupted by user")
    except Exception as e:
        print(f"Parser error: {e}")
    finally:
        await parser.stop()

if __name__ == "__main__":
    asyncio.run(main())