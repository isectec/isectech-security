#!/usr/bin/env python3
"""
iSECTECH SIEM Log Normalizer
Production-grade log normalization engine with ECS compliance
Extends the custom log parser with comprehensive field standardization
"""

import re
import json
import yaml
import asyncio
import logging
import hashlib
import ipaddress
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Union, Tuple
from dataclasses import dataclass
from pathlib import Path
import aiofiles
import geoip2.database
import geoip2.errors
from user_agents import parse as parse_user_agent
import dns.resolver
import dns.reversename

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class NormalizationConfig:
    """Configuration for log normalization"""
    ecs_mapping_file: str
    geoip_database: str = "/opt/geoip/GeoLite2-City.mmdb"
    dns_timeout: int = 1000
    dns_cache_ttl: int = 3600
    max_field_length: int = 32768
    enable_geoip: bool = True
    enable_user_agent: bool = True
    enable_dns_lookup: bool = False
    drop_invalid_entries: bool = False
    validate_ecs_compliance: bool = True

@dataclass
class NormalizedLog:
    """Normalized log entry with ECS compliance"""
    timestamp: datetime
    raw_log: str
    normalized_fields: Dict[str, Any]
    metadata: Dict[str, Any]
    validation_errors: List[str]
    enrichment_data: Dict[str, Any]
    fingerprint: str
    ecs_version: str = "8.11.0"

class LogNormalizer:
    """
    Production-grade log normalization engine for iSECTECH SIEM
    Implements ECS (Elastic Common Schema) compliance with custom enrichment
    """
    
    def __init__(self, config: NormalizationConfig):
        self.config = config
        self.ecs_mapping = {}
        self.dns_cache = {}
        self.geoip_reader = None
        self.stats = {
            "total_processed": 0,
            "successfully_normalized": 0,
            "validation_errors": 0,
            "enrichment_failures": 0,
            "performance_metrics": {}
        }
        
    async def initialize(self):
        """Initialize the normalizer with configuration and databases"""
        try:
            # Load ECS field mapping
            await self._load_ecs_mapping()
            
            # Initialize GeoIP database
            if self.config.enable_geoip:
                await self._initialize_geoip()
                
            logger.info("Log normalizer initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize log normalizer: {e}")
            raise
            
    async def _load_ecs_mapping(self):
        """Load ECS field mapping configuration"""
        try:
            async with aiofiles.open(self.config.ecs_mapping_file, 'r') as f:
                content = await f.read()
                self.ecs_mapping = yaml.safe_load(content)
                logger.info(f"Loaded ECS mapping with version {self.ecs_mapping.get('version', 'unknown')}")
                
        except Exception as e:
            logger.error(f"Failed to load ECS mapping: {e}")
            raise
            
    async def _initialize_geoip(self):
        """Initialize GeoIP database reader"""
        try:
            if Path(self.config.geoip_database).exists():
                self.geoip_reader = geoip2.database.Reader(self.config.geoip_database)
                logger.info("GeoIP database initialized")
            else:
                logger.warning(f"GeoIP database not found: {self.config.geoip_database}")
                self.config.enable_geoip = False
                
        except Exception as e:
            logger.error(f"Failed to initialize GeoIP database: {e}")
            self.config.enable_geoip = False
            
    async def normalize_log(self, raw_log: str, log_format: str = "auto") -> Optional[NormalizedLog]:
        """
        Normalize a raw log entry to ECS compliance
        
        Args:
            raw_log: Raw log string
            log_format: Log format type (auto-detect if not specified)
            
        Returns:
            NormalizedLog object or None if normalization fails
        """
        start_time = datetime.now()
        self.stats["total_processed"] += 1
        
        try:
            # Parse raw log to structured format
            parsed_fields = await self._parse_raw_log(raw_log, log_format)
            if not parsed_fields:
                return None
                
            # Apply ECS field mapping
            normalized_fields = await self._apply_ecs_mapping(parsed_fields)
            
            # Perform field transformations
            normalized_fields = await self._apply_transformations(normalized_fields)
            
            # Data type conversions
            normalized_fields = await self._convert_data_types(normalized_fields)
            
            # Validate normalized fields
            validation_errors = await self._validate_fields(normalized_fields)
            
            # Enrich with additional data
            enrichment_data = await self._enrich_log_data(normalized_fields)
            
            # Generate fingerprint
            fingerprint = await self._generate_fingerprint(normalized_fields)
            
            # Create normalized log object
            normalized_log = NormalizedLog(
                timestamp=normalized_fields.get("@timestamp", datetime.now(timezone.utc)),
                raw_log=raw_log,
                normalized_fields=normalized_fields,
                metadata={
                    "log_format": log_format,
                    "normalization_time": (datetime.now() - start_time).total_seconds(),
                    "source": "isectech-siem"
                },
                validation_errors=validation_errors,
                enrichment_data=enrichment_data,
                fingerprint=fingerprint
            )
            
            if not validation_errors or not self.config.drop_invalid_entries:
                self.stats["successfully_normalized"] += 1
                return normalized_log
            else:
                self.stats["validation_errors"] += 1
                return None if self.config.drop_invalid_entries else normalized_log
                
        except Exception as e:
            logger.error(f"Failed to normalize log: {e}")
            return None
            
    async def _parse_raw_log(self, raw_log: str, log_format: str) -> Optional[Dict[str, Any]]:
        """Parse raw log based on format detection or specified format"""
        try:
            # Auto-detect format if not specified
            if log_format == "auto":
                log_format = await self._detect_log_format(raw_log)
                
            # JSON format
            if log_format == "json":
                return json.loads(raw_log.strip())
                
            # CSV format (simple implementation)
            elif log_format == "csv":
                return await self._parse_csv_log(raw_log)
                
            # Syslog format
            elif log_format == "syslog":
                return await self._parse_syslog(raw_log)
                
            # Windows Event Log
            elif log_format == "windows_event":
                return await self._parse_windows_event(raw_log)
                
            # Apache/Nginx access log
            elif log_format in ["apache", "nginx"]:
                return await self._parse_web_access_log(raw_log)
                
            # Custom regex patterns
            else:
                return await self._parse_custom_format(raw_log, log_format)
                
        except Exception as e:
            logger.warning(f"Failed to parse log format {log_format}: {e}")
            return None
            
    async def _detect_log_format(self, raw_log: str) -> str:
        """Auto-detect log format based on content analysis"""
        log_line = raw_log.strip()
        
        # JSON detection
        if log_line.startswith('{') and log_line.endswith('}'):
            try:
                json.loads(log_line)
                return "json"
            except:
                pass
                
        # Syslog detection (RFC3164/RFC5424)
        if re.match(r'^<\d+>', log_line) or re.match(r'^\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}', log_line):
            return "syslog"
            
        # Windows Event Log XML
        if log_line.startswith('<Event xmlns='):
            return "windows_event"
            
        # Apache/Nginx Common Log Format
        if re.match(r'^\S+ \S+ \S+ \[[\d/\w:+\s]+\] "\w+ \S+ HTTP/[\d.]+" \d+ \d+', log_line):
            return "apache"
            
        # CSV detection
        if ',' in log_line and len(log_line.split(',')) > 3:
            return "csv"
            
        return "unknown"
        
    async def _parse_csv_log(self, raw_log: str) -> Dict[str, Any]:
        """Parse CSV format log"""
        fields = raw_log.strip().split(',')
        return {f"field_{i}": field.strip('"') for i, field in enumerate(fields)}
        
    async def _parse_syslog(self, raw_log: str) -> Dict[str, Any]:
        """Parse syslog format (RFC3164/RFC5424)"""
        # RFC3164 pattern
        rfc3164_pattern = r'^<(\d+)>(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(.+?):\s*(.*)$'
        match = re.match(rfc3164_pattern, raw_log.strip())
        
        if match:
            priority, timestamp_str, hostname, program, message = match.groups()
            return {
                "priority": int(priority),
                "timestamp": timestamp_str,
                "hostname": hostname,
                "program": program,
                "message": message,
                "facility": int(priority) >> 3,
                "severity": int(priority) & 7
            }
            
        # RFC5424 pattern (simplified)
        rfc5424_pattern = r'^<(\d+)>(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s*(.*)$'
        match = re.match(rfc5424_pattern, raw_log.strip())
        
        if match:
            priority, version, timestamp_str, hostname, app_name, proc_id, msg_id, message = match.groups()
            return {
                "priority": int(priority),
                "version": int(version),
                "timestamp": timestamp_str,
                "hostname": hostname,
                "app_name": app_name,
                "proc_id": proc_id,
                "msg_id": msg_id,
                "message": message,
                "facility": int(priority) >> 3,
                "severity": int(priority) & 7
            }
            
        return {"raw_message": raw_log.strip()}
        
    async def _parse_windows_event(self, raw_log: str) -> Dict[str, Any]:
        """Parse Windows Event Log XML format"""
        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(raw_log)
            
            # Extract key fields from Windows Event XML
            event_data = {}
            
            # System information
            system = root.find('.//{http://schemas.microsoft.com/win/2004/08/events/event}System')
            if system is not None:
                for child in system:
                    tag = child.tag.split('}')[-1] if '}' in child.tag else child.tag
                    event_data[f"system_{tag.lower()}"] = child.text or child.attrib
                    
            # Event data
            event_data_elem = root.find('.//{http://schemas.microsoft.com/win/2004/08/events/event}EventData')
            if event_data_elem is not None:
                for data in event_data_elem.findall('.//{http://schemas.microsoft.com/win/2004/08/events/event}Data'):
                    name = data.get('Name', f'data_{len(event_data)}')
                    event_data[name] = data.text
                    
            return event_data
            
        except Exception as e:
            logger.warning(f"Failed to parse Windows Event XML: {e}")
            return {"raw_event": raw_log.strip()}
            
    async def _parse_web_access_log(self, raw_log: str) -> Dict[str, Any]:
        """Parse Apache/Nginx access log (Common Log Format)"""
        # Common Log Format pattern
        clf_pattern = r'^(\S+) (\S+) (\S+) \[([\w:/]+\s[+\-]\d{4})\] "(\S+) (\S+) (\S+)" (\d+) (\d+)(?:\s+"([^"]*)")?(?:\s+"([^"]*)")?'
        match = re.match(clf_pattern, raw_log.strip())
        
        if match:
            groups = match.groups()
            return {
                "client_ip": groups[0],
                "identity": groups[1],
                "username": groups[2],
                "timestamp": groups[3],
                "method": groups[4],
                "request_uri": groups[5],
                "protocol": groups[6],
                "status_code": int(groups[7]),
                "response_size": int(groups[8]) if groups[8] != '-' else 0,
                "referer": groups[9] if len(groups) > 9 and groups[9] else None,
                "user_agent": groups[10] if len(groups) > 10 and groups[10] else None
            }
            
        return {"raw_access_log": raw_log.strip()}
        
    async def _parse_custom_format(self, raw_log: str, log_format: str) -> Dict[str, Any]:
        """Parse using custom format patterns"""
        # This would integrate with the custom format definitions from task 40.7
        # For now, return basic parsing
        return {"raw_log": raw_log.strip(), "format": log_format}
        
    async def _apply_ecs_mapping(self, parsed_fields: Dict[str, Any]) -> Dict[str, Any]:
        """Apply ECS field mapping to parsed fields"""
        normalized = {}
        
        # Get all field mappings from ECS configuration
        all_mappings = {}
        for category in ["event_fields", "host_fields", "user_fields", "process_fields", 
                        "network_fields", "file_fields", "threat_fields", "registry_fields",
                        "url_fields", "geo_fields", "rule_fields", "isectech_fields"]:
            if category in self.ecs_mapping:
                all_mappings.update(self.ecs_mapping[category])
                
        # Apply mappings
        for source_field, target_config in all_mappings.items():
            if source_field in parsed_fields:
                ecs_field = target_config.get("ecs_field")
                if ecs_field:
                    value = parsed_fields[source_field]
                    
                    # Apply allowed values validation
                    if "allowed_values" in target_config:
                        if value not in target_config["allowed_values"]:
                            continue
                            
                    # Apply range validation
                    if "range" in target_config and isinstance(value, (int, float)):
                        min_val, max_val = target_config["range"]
                        if not (min_val <= value <= max_val):
                            continue
                            
                    normalized[ecs_field] = value
                    
        # Add default fields
        if "@timestamp" not in normalized:
            normalized["@timestamp"] = datetime.now(timezone.utc)
            
        if "ecs.version" not in normalized:
            normalized["ecs.version"] = self.ecs_mapping.get("ecs_version", "8.11")
            
        return normalized
        
    async def _apply_transformations(self, normalized_fields: Dict[str, Any]) -> Dict[str, Any]:
        """Apply field transformations defined in ECS mapping"""
        if "transformations" not in self.ecs_mapping:
            return normalized_fields
            
        transformations = self.ecs_mapping["transformations"]
        
        # Severity normalization
        if "severity_normalization" in transformations:
            transform = transformations["severity_normalization"]
            input_field = transform["input_field"]
            output_field = transform["output_field"]
            
            if input_field in normalized_fields:
                value = str(normalized_fields[input_field]).lower()
                normalized_value = transform["mapping"].get(value, transform.get("default", 0))
                normalized_fields[output_field] = normalized_value
                
        # Outcome normalization
        if "outcome_normalization" in transformations:
            transform = transformations["outcome_normalization"]
            input_field = transform["input_field"]
            output_field = transform["output_field"]
            
            if input_field in normalized_fields:
                value = str(normalized_fields[input_field]).lower()
                normalized_value = transform["mapping"].get(value, transform.get("default", "unknown"))
                normalized_fields[output_field] = normalized_value
                
        # Protocol normalization
        if "protocol_normalization" in transformations:
            transform = transformations["protocol_normalization"]
            input_field = transform["input_field"]
            output_field = transform["output_field"]
            
            if input_field in normalized_fields:
                value = str(normalized_fields[input_field])
                if transform.get("case_insensitive", False):
                    value = value.lower()
                    
                normalized_value = transform["mapping"].get(value, value)
                normalized_fields[output_field] = normalized_value
                
                if transform.get("preserve_original", False):
                    normalized_fields[f"{output_field}_original"] = normalized_fields[input_field]
                    
        return normalized_fields
        
    async def _convert_data_types(self, normalized_fields: Dict[str, Any]) -> Dict[str, Any]:
        """Convert data types according to ECS specifications"""
        if "type_conversions" not in self.ecs_mapping:
            return normalized_fields
            
        conversions = self.ecs_mapping["type_conversions"]
        
        # String to IP conversion
        for field in conversions.get("string_to_ip", []):
            if field in normalized_fields:
                try:
                    ip_value = str(normalized_fields[field])
                    ipaddress.ip_address(ip_value)  # Validate IP
                    normalized_fields[field] = ip_value
                except:
                    logger.warning(f"Invalid IP address in field {field}: {normalized_fields[field]}")
                    del normalized_fields[field]
                    
        # String to long conversion
        for field in conversions.get("string_to_long", []):
            if field in normalized_fields:
                try:
                    normalized_fields[field] = int(normalized_fields[field])
                except:
                    logger.warning(f"Cannot convert to long in field {field}: {normalized_fields[field]}")
                    del normalized_fields[field]
                    
        # String to date conversion
        for field in conversions.get("string_to_date", []):
            if field in normalized_fields:
                normalized_fields[field] = await self._parse_timestamp(normalized_fields[field])
                
        # String to float conversion
        for field in conversions.get("string_to_float", []):
            if field in normalized_fields:
                try:
                    normalized_fields[field] = float(normalized_fields[field])
                except:
                    logger.warning(f"Cannot convert to float in field {field}: {normalized_fields[field]}")
                    del normalized_fields[field]
                    
        return normalized_fields
        
    async def _parse_timestamp(self, timestamp_value: Any) -> datetime:
        """Parse timestamp from various formats"""
        if isinstance(timestamp_value, datetime):
            return timestamp_value
            
        timestamp_str = str(timestamp_value)
        
        # Epoch milliseconds
        if timestamp_str.isdigit() and len(timestamp_str) == 13:
            return datetime.fromtimestamp(int(timestamp_str) / 1000, timezone.utc)
            
        # Epoch seconds
        elif timestamp_str.isdigit() and len(timestamp_str) == 10:
            return datetime.fromtimestamp(int(timestamp_str), timezone.utc)
            
        # ISO 8601 format
        elif 'T' in timestamp_str:
            try:
                return datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            except:
                pass
                
        # Common log formats
        formats = [
            "%Y-%m-%d %H:%M:%S",
            "%Y/%m/%d %H:%M:%S",
            "%b %d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S.%f"
        ]
        
        for fmt in formats:
            try:
                return datetime.strptime(timestamp_str, fmt).replace(tzinfo=timezone.utc)
            except:
                continue
                
        # Default to current time if parsing fails
        logger.warning(f"Could not parse timestamp: {timestamp_value}")
        return datetime.now(timezone.utc)
        
    async def _validate_fields(self, normalized_fields: Dict[str, Any]) -> List[str]:
        """Validate normalized fields against ECS requirements"""
        errors = []
        
        if "validation" not in self.ecs_mapping:
            return errors
            
        validation = self.ecs_mapping["validation"]
        
        # Required fields validation
        if "required_fields" in validation:
            for field in validation["required_fields"]:
                if field not in normalized_fields:
                    errors.append(f"Missing required field: {field}")
                    
        # IP validation
        if "ip_validation" in validation:
            ip_config = validation["ip_validation"]
            pattern = re.compile(ip_config["pattern"])
            for field in ip_config["fields"]:
                if field in normalized_fields:
                    if not pattern.match(str(normalized_fields[field])):
                        errors.append(f"Invalid IP format in field {field}: {normalized_fields[field]}")
                        
        # Port validation
        if "port_validation" in validation:
            port_config = validation["port_validation"]
            min_port, max_port = port_config["range"]
            for field in port_config["fields"]:
                if field in normalized_fields:
                    try:
                        port = int(normalized_fields[field])
                        if not (min_port <= port <= max_port):
                            errors.append(f"Port out of range in field {field}: {port}")
                    except:
                        errors.append(f"Invalid port format in field {field}: {normalized_fields[field]}")
                        
        # Timestamp validation
        if "timestamp_validation" in validation:
            ts_config = validation["timestamp_validation"]
            field = ts_config["field"]
            if field in normalized_fields:
                timestamp = normalized_fields[field]
                now = datetime.now(timezone.utc)
                
                # Check if timestamp is too old
                max_age = now.timestamp() - (ts_config["max_age_hours"] * 3600)
                if timestamp.timestamp() < max_age:
                    errors.append(f"Timestamp too old: {timestamp}")
                    
                # Check if timestamp is too far in the future
                future_tolerance = now.timestamp() + (ts_config["future_tolerance_minutes"] * 60)
                if timestamp.timestamp() > future_tolerance:
                    errors.append(f"Timestamp too far in future: {timestamp}")
                    
        return errors
        
    async def _enrich_log_data(self, normalized_fields: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich log data with additional context"""
        enrichment_data = {}
        
        try:
            # GeoIP enrichment
            if self.config.enable_geoip and self.geoip_reader:
                enrichment_data.update(await self._enrich_geoip(normalized_fields))
                
            # User agent enrichment
            if self.config.enable_user_agent:
                enrichment_data.update(await self._enrich_user_agent(normalized_fields))
                
            # DNS enrichment
            if self.config.enable_dns_lookup:
                enrichment_data.update(await self._enrich_dns(normalized_fields))
                
        except Exception as e:
            logger.warning(f"Enrichment failed: {e}")
            self.stats["enrichment_failures"] += 1
            
        return enrichment_data
        
    async def _enrich_geoip(self, normalized_fields: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich with GeoIP data"""
        enrichment = {}
        
        for ip_field in ["source.ip", "destination.ip"]:
            if ip_field in normalized_fields:
                try:
                    ip_addr = normalized_fields[ip_field]
                    response = self.geoip_reader.city(ip_addr)
                    
                    prefix = ip_field.split('.')[0]  # source or destination
                    enrichment[f"{prefix}.geo.country_name"] = response.country.name
                    enrichment[f"{prefix}.geo.country_iso_code"] = response.country.iso_code
                    enrichment[f"{prefix}.geo.city_name"] = response.city.name
                    enrichment[f"{prefix}.geo.location"] = {
                        "lat": float(response.location.latitude),
                        "lon": float(response.location.longitude)
                    }
                    
                except (geoip2.errors.AddressNotFoundError, ValueError):
                    pass  # IP not found in database or invalid IP
                    
        return enrichment
        
    async def _enrich_user_agent(self, normalized_fields: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich with user agent parsing"""
        enrichment = {}
        
        if "user_agent.original" in normalized_fields:
            try:
                ua_string = normalized_fields["user_agent.original"]
                parsed_ua = parse_user_agent(ua_string)
                
                enrichment["user_agent.device.name"] = parsed_ua.device.family
                enrichment["user_agent.name"] = parsed_ua.browser.family
                enrichment["user_agent.version"] = parsed_ua.browser.version_string
                enrichment["user_agent.os.name"] = parsed_ua.os.family
                enrichment["user_agent.os.version"] = parsed_ua.os.version_string
                
            except Exception as e:
                logger.warning(f"User agent parsing failed: {e}")
                
        return enrichment
        
    async def _enrich_dns(self, normalized_fields: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich with DNS reverse lookups"""
        enrichment = {}
        
        for ip_field in ["source.ip", "destination.ip"]:
            if ip_field in normalized_fields:
                ip_addr = normalized_fields[ip_field]
                
                # Check cache first
                if ip_addr in self.dns_cache:
                    cache_entry = self.dns_cache[ip_addr]
                    if datetime.now().timestamp() - cache_entry["timestamp"] < self.config.dns_cache_ttl:
                        prefix = ip_field.split('.')[0]
                        enrichment[f"{prefix}.domain"] = cache_entry["domain"]
                        continue
                        
                # Perform DNS lookup
                try:
                    reverse_name = dns.reversename.from_address(ip_addr)
                    domain = str(dns.resolver.resolve(reverse_name, "PTR")[0]).rstrip('.')
                    
                    # Cache result
                    self.dns_cache[ip_addr] = {
                        "domain": domain,
                        "timestamp": datetime.now().timestamp()
                    }
                    
                    prefix = ip_field.split('.')[0]
                    enrichment[f"{prefix}.domain"] = domain
                    
                except:
                    pass  # DNS lookup failed
                    
        return enrichment
        
    async def _generate_fingerprint(self, normalized_fields: Dict[str, Any]) -> str:
        """Generate unique fingerprint for log entry"""
        # Create fingerprint from key fields
        key_fields = []
        
        for field in ["@timestamp", "source.ip", "destination.ip", "event.action", "host.name"]:
            if field in normalized_fields:
                key_fields.append(f"{field}={normalized_fields[field]}")
                
        fingerprint_data = "|".join(key_fields)
        return hashlib.sha256(fingerprint_data.encode()).hexdigest()[:16]
        
    async def normalize_batch(self, log_entries: List[str], log_format: str = "auto") -> List[NormalizedLog]:
        """Normalize a batch of log entries efficiently"""
        tasks = []
        for log_entry in log_entries:
            task = asyncio.create_task(self.normalize_log(log_entry, log_format))
            tasks.append(task)
            
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter out exceptions and None results
        normalized_logs = []
        for result in results:
            if isinstance(result, NormalizedLog):
                normalized_logs.append(result)
            elif isinstance(result, Exception):
                logger.error(f"Batch normalization error: {result}")
                
        return normalized_logs
        
    async def get_statistics(self) -> Dict[str, Any]:
        """Get normalization statistics"""
        return {
            **self.stats,
            "success_rate": (self.stats["successfully_normalized"] / max(self.stats["total_processed"], 1)) * 100,
            "dns_cache_size": len(self.dns_cache)
        }
        
    async def cleanup(self):
        """Cleanup resources"""
        if self.geoip_reader:
            self.geoip_reader.close()
            
        self.dns_cache.clear()
        logger.info("Log normalizer cleanup completed")

# Example usage
async def main():
    """Example usage of the log normalizer"""
    config = NormalizationConfig(
        ecs_mapping_file="/Users/cf-215/Documents/isectech/siem/log-processing/ecs-field-mapping.yaml",
        enable_geoip=True,
        enable_user_agent=True,
        enable_dns_lookup=False
    )
    
    normalizer = LogNormalizer(config)
    await normalizer.initialize()
    
    # Example log entries
    test_logs = [
        '{"timestamp": "2024-01-15T10:30:00Z", "source_ip": "192.168.1.100", "event_action": "login", "user_name": "admin"}',
        '<30>Jan 15 10:30:00 server01 sshd[1234]: Accepted password for admin from 192.168.1.100 port 22 ssh2',
        '192.168.1.100 - admin [15/Jan/2024:10:30:00 +0000] "GET /api/users HTTP/1.1" 200 1234'
    ]
    
    # Normalize logs
    for log_entry in test_logs:
        normalized = await normalizer.normalize_log(log_entry)
        if normalized:
            print(f"Normalized: {json.dumps(normalized.normalized_fields, indent=2, default=str)}")
            print(f"Fingerprint: {normalized.fingerprint}")
            print("---")
            
    # Get statistics
    stats = await normalizer.get_statistics()
    print(f"Statistics: {json.dumps(stats, indent=2)}")
    
    await normalizer.cleanup()

if __name__ == "__main__":
    asyncio.run(main())