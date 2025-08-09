#!/usr/bin/env python3
"""
iSECTECH SIEM Log Format Validator
Validation engine for custom log formats and parsing rules
"""

import re
import json
import yaml
import ipaddress
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from pathlib import Path

# ═══════════════════════════════════════════════════════════════════════════════
# VALIDATION RULES AND DATA STRUCTURES
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class ValidationResult:
    """Validation result structure"""
    valid: bool
    errors: List[str]
    warnings: List[str]
    field_validations: Dict[str, bool]
    
    def __post_init__(self):
        if self.errors is None:
            self.errors = []
        if self.warnings is None:
            self.warnings = []
        if self.field_validations is None:
            self.field_validations = {}

class LogFormatValidator:
    """Advanced log format validator"""
    
    def __init__(self):
        self.validation_rules = {
            # Basic field validation
            "require_timestamp": self._validate_timestamp_required,
            "require_source_ip": self._validate_source_ip_required,
            "require_event_type": self._validate_event_type_required,
            "require_message": self._validate_message_required,
            "require_severity": self._validate_severity_required,
            
            # Specific field validation
            "validate_timestamp": self._validate_timestamp_format,
            "validate_ip_addresses": self._validate_ip_addresses,
            "validate_ports": self._validate_ports,
            "validate_process_ids": self._validate_process_ids,
            "validate_hashes": self._validate_hashes,
            "validate_urls": self._validate_urls,
            "validate_email": self._validate_email,
            "validate_domains": self._validate_domains,
            
            # Security validation
            "validate_user_names": self._validate_user_names,
            "validate_file_paths": self._validate_file_paths,
            "validate_command_lines": self._validate_command_lines,
            "validate_registry_keys": self._validate_registry_keys,
            
            # Network validation
            "validate_protocols": self._validate_protocols,
            "validate_network_direction": self._validate_network_direction,
            "validate_geoip": self._validate_geoip,
            
            # Authentication validation
            "validate_authentication": self._validate_authentication,
            "validate_session_ids": self._validate_session_ids,
            
            # Threat intelligence validation
            "validate_threat_indicators": self._validate_threat_indicators,
            "validate_mitre_techniques": self._validate_mitre_techniques,
            
            # Data consistency validation
            "validate_process_hierarchy": self._validate_process_hierarchy,
            "validate_network_flow": self._validate_network_flow,
            "validate_time_sequence": self._validate_time_sequence
        }
        
        # Compile common regex patterns
        self.patterns = {
            "ipv4": re.compile(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'),
            "ipv6": re.compile(r'^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$'),
            "email": re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'),
            "domain": re.compile(r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'),
            "md5": re.compile(r'^[a-fA-F0-9]{32}$'),
            "sha1": re.compile(r'^[a-fA-F0-9]{40}$'),
            "sha256": re.compile(r'^[a-fA-F0-9]{64}$'),
            "sha512": re.compile(r'^[a-fA-F0-9]{128}$'),
            "url": re.compile(r'^https?://(?:[-\w.])+(?:\:[0-9]+)?(?:/(?:[\w/_.])*(?:\?(?:[\w&=%.])*)?(?:\#(?:[\w.])*)?)?$'),
            "windows_path": re.compile(r'^[a-zA-Z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*$'),
            "unix_path": re.compile(r'^/(?:[^/\0]+/?)*$'),
            "process_name": re.compile(r'^[a-zA-Z0-9_.-]+(?:\.exe)?$'),
            "session_id": re.compile(r'^[0-9a-fA-F-]{8,}$'),
            "guid": re.compile(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')
        }
        
        # Load MITRE ATT&CK techniques (simplified)
        self.mitre_techniques = self._load_mitre_techniques()
        
        # Load common threat indicators
        self.threat_indicators = self._load_threat_indicators()
    
    def _load_mitre_techniques(self) -> Dict[str, str]:
        """Load MITRE ATT&CK technique mappings"""
        # This would normally load from a comprehensive MITRE ATT&CK database
        return {
            "T1003": "OS Credential Dumping",
            "T1055": "Process Injection",
            "T1059": "Command and Scripting Interpreter",
            "T1082": "System Information Discovery",
            "T1083": "File and Directory Discovery",
            "T1087": "Account Discovery",
            "T1090": "Proxy",
            "T1105": "Ingress Tool Transfer",
            "T1134": "Access Token Manipulation",
            "T1190": "Exploit Public-Facing Application",
            "T1210": "Exploitation of Remote Services",
            "T1566": "Phishing",
            "T1078": "Valid Accounts"
        }
    
    def _load_threat_indicators(self) -> Dict[str, List[str]]:
        """Load threat indicator patterns"""
        return {
            "malicious_domains": [
                "badsite.com",
                "malware-c2.net",
                "phishing-site.org"
            ],
            "suspicious_processes": [
                "powershell.exe",
                "cmd.exe",
                "wscript.exe",
                "cscript.exe",
                "regsvr32.exe",
                "rundll32.exe"
            ],
            "attack_patterns": [
                "mimikatz",
                "cobalt strike",
                "metasploit",
                "empire"
            ]
        }
    
    def validate_parsed_log(self, parsed_fields: Dict[str, Any], validation_rules: List[str]) -> ValidationResult:
        """Validate a parsed log against specified rules"""
        result = ValidationResult(
            valid=True,
            errors=[],
            warnings=[],
            field_validations={}
        )
        
        # Apply each validation rule
        for rule_name in validation_rules:
            if rule_name in self.validation_rules:
                try:
                    rule_result = self.validation_rules[rule_name](parsed_fields)
                    
                    if not rule_result.valid:
                        result.valid = False
                        result.errors.extend(rule_result.errors)
                    
                    result.warnings.extend(rule_result.warnings)
                    result.field_validations.update(rule_result.field_validations)
                    
                except Exception as e:
                    result.valid = False
                    result.errors.append(f"Validation rule '{rule_name}' failed: {str(e)}")
            else:
                result.warnings.append(f"Unknown validation rule: {rule_name}")
        
        return result
    
    # ═══════════════════════════════════════════════════════════════════════════════
    # BASIC FIELD VALIDATION
    # ═══════════════════════════════════════════════════════════════════════════════
    
    def _validate_timestamp_required(self, fields: Dict[str, Any]) -> ValidationResult:
        """Validate that timestamp field is present"""
        result = ValidationResult(valid=True, errors=[], warnings=[], field_validations={})
        
        timestamp_fields = ["timestamp", "@timestamp", "time", "eventTime", "logTime"]
        has_timestamp = any(field in fields for field in timestamp_fields)
        
        if not has_timestamp:
            result.valid = False
            result.errors.append("No timestamp field found")
        
        result.field_validations["timestamp_present"] = has_timestamp
        return result
    
    def _validate_source_ip_required(self, fields: Dict[str, Any]) -> ValidationResult:
        """Validate that source IP field is present"""
        result = ValidationResult(valid=True, errors=[], warnings=[], field_validations={})
        
        ip_fields = ["source.ip", "src_ip", "source_ip", "sourceAddress", "client_ip", "remote_addr"]
        has_source_ip = any(field in fields for field in ip_fields)
        
        if not has_source_ip:
            result.valid = False
            result.errors.append("No source IP field found")
        
        result.field_validations["source_ip_present"] = has_source_ip
        return result
    
    def _validate_event_type_required(self, fields: Dict[str, Any]) -> ValidationResult:
        """Validate that event type field is present"""
        result = ValidationResult(valid=True, errors=[], warnings=[], field_validations={})
        
        event_fields = ["event.action", "eventType", "event_type", "action", "activity"]
        has_event_type = any(field in fields for field in event_fields)
        
        if not has_event_type:
            result.valid = False
            result.errors.append("No event type field found")
        
        result.field_validations["event_type_present"] = has_event_type
        return result
    
    def _validate_message_required(self, fields: Dict[str, Any]) -> ValidationResult:
        """Validate that message field is present"""
        result = ValidationResult(valid=True, errors=[], warnings=[], field_validations={})
        
        message_fields = ["message", "msg", "description", "summary", "details"]
        has_message = any(field in fields for field in message_fields)
        
        if not has_message:
            result.valid = False
            result.errors.append("No message field found")
        
        result.field_validations["message_present"] = has_message
        return result
    
    def _validate_severity_required(self, fields: Dict[str, Any]) -> ValidationResult:
        """Validate that severity field is present"""
        result = ValidationResult(valid=True, errors=[], warnings=[], field_validations={})
        
        severity_fields = ["event.severity", "severity", "level", "priority", "criticality"]
        has_severity = any(field in fields for field in severity_fields)
        
        if not has_severity:
            result.warnings.append("No severity field found")
        
        result.field_validations["severity_present"] = has_severity
        return result
    
    # ═══════════════════════════════════════════════════════════════════════════════
    # SPECIFIC FIELD VALIDATION
    # ═══════════════════════════════════════════════════════════════════════════════
    
    def _validate_timestamp_format(self, fields: Dict[str, Any]) -> ValidationResult:
        """Validate timestamp format"""
        result = ValidationResult(valid=True, errors=[], warnings=[], field_validations={})
        
        timestamp_fields = ["timestamp", "@timestamp", "time", "eventTime", "logTime"]
        
        for field in timestamp_fields:
            if field in fields:
                timestamp_value = fields[field]
                
                if isinstance(timestamp_value, str):
                    # Try common timestamp formats
                    valid_formats = [
                        "%Y-%m-%dT%H:%M:%S.%fZ",
                        "%Y-%m-%dT%H:%M:%SZ",
                        "%Y-%m-%d %H:%M:%S",
                        "%d/%b/%Y:%H:%M:%S %z",
                        "%Y/%m/%d %H:%M:%S"
                    ]
                    
                    timestamp_valid = False
                    for fmt in valid_formats:
                        try:
                            datetime.strptime(timestamp_value, fmt)
                            timestamp_valid = True
                            break
                        except ValueError:
                            continue
                    
                    # Try ISO 8601
                    if not timestamp_valid:
                        try:
                            datetime.fromisoformat(timestamp_value.replace('Z', '+00:00'))
                            timestamp_valid = True
                        except ValueError:
                            pass
                    
                    # Try epoch timestamp
                    if not timestamp_valid:
                        try:
                            float(timestamp_value)
                            timestamp_valid = True
                        except ValueError:
                            pass
                    
                    if not timestamp_valid:
                        result.errors.append(f"Invalid timestamp format: {timestamp_value}")
                        result.valid = False
                    
                    result.field_validations[f"{field}_valid"] = timestamp_valid
                
                elif isinstance(timestamp_value, (int, float)):
                    # Epoch timestamp
                    result.field_validations[f"{field}_valid"] = True
                else:
                    result.errors.append(f"Invalid timestamp type: {type(timestamp_value)}")
                    result.valid = False
                    result.field_validations[f"{field}_valid"] = False
        
        return result
    
    def _validate_ip_addresses(self, fields: Dict[str, Any]) -> ValidationResult:
        """Validate IP address fields"""
        result = ValidationResult(valid=True, errors=[], warnings=[], field_validations={})
        
        ip_fields = [
            "source.ip", "destination.ip", "src_ip", "dst_ip", "client_ip", "server_ip",
            "sourceAddress", "destinationAddress", "remote_addr", "local_addr"
        ]
        
        for field in ip_fields:
            if field in fields:
                ip_value = str(fields[field])
                
                if ip_value and ip_value != "":
                    try:
                        ipaddress.ip_address(ip_value)
                        result.field_validations[f"{field}_valid"] = True
                    except ValueError:
                        result.errors.append(f"Invalid IP address: {ip_value}")
                        result.valid = False
                        result.field_validations[f"{field}_valid"] = False
        
        return result
    
    def _validate_ports(self, fields: Dict[str, Any]) -> ValidationResult:
        """Validate port number fields"""
        result = ValidationResult(valid=True, errors=[], warnings=[], field_validations={})
        
        port_fields = [
            "source.port", "destination.port", "src_port", "dst_port", "local_port", "remote_port"
        ]
        
        for field in port_fields:
            if field in fields:
                port_value = fields[field]
                
                if port_value is not None:
                    try:
                        port_num = int(port_value)
                        if 1 <= port_num <= 65535:
                            result.field_validations[f"{field}_valid"] = True
                        else:
                            result.errors.append(f"Port out of range: {port_num}")
                            result.valid = False
                            result.field_validations[f"{field}_valid"] = False
                    except (ValueError, TypeError):
                        result.errors.append(f"Invalid port number: {port_value}")
                        result.valid = False
                        result.field_validations[f"{field}_valid"] = False
        
        return result
    
    def _validate_process_ids(self, fields: Dict[str, Any]) -> ValidationResult:
        """Validate process ID fields"""
        result = ValidationResult(valid=True, errors=[], warnings=[], field_validations={})
        
        pid_fields = [
            "process.pid", "process.parent.pid", "ProcessId", "ParentProcessId", "pid", "ppid"
        ]
        
        for field in pid_fields:
            if field in fields:
                pid_value = fields[field]
                
                if pid_value is not None:
                    try:
                        pid_num = int(pid_value)
                        if pid_num >= 0:
                            result.field_validations[f"{field}_valid"] = True
                        else:
                            result.errors.append(f"Invalid process ID: {pid_num}")
                            result.valid = False
                            result.field_validations[f"{field}_valid"] = False
                    except (ValueError, TypeError):
                        result.errors.append(f"Invalid process ID format: {pid_value}")
                        result.valid = False
                        result.field_validations[f"{field}_valid"] = False
        
        return result
    
    def _validate_hashes(self, fields: Dict[str, Any]) -> ValidationResult:
        """Validate hash fields"""
        result = ValidationResult(valid=True, errors=[], warnings=[], field_validations={})
        
        hash_fields = {
            "md5": ["file.hash.md5", "MD5", "md5", "hash_md5"],
            "sha1": ["file.hash.sha1", "SHA1", "sha1", "hash_sha1"],
            "sha256": ["file.hash.sha256", "SHA256", "sha256", "hash_sha256"],
            "sha512": ["file.hash.sha512", "SHA512", "sha512", "hash_sha512"]
        }
        
        for hash_type, field_names in hash_fields.items():
            for field in field_names:
                if field in fields:
                    hash_value = str(fields[field])
                    
                    if hash_value and hash_value != "":
                        pattern = self.patterns[hash_type]
                        if pattern.match(hash_value):
                            result.field_validations[f"{field}_valid"] = True
                        else:
                            result.errors.append(f"Invalid {hash_type.upper()} hash: {hash_value}")
                            result.valid = False
                            result.field_validations[f"{field}_valid"] = False
        
        return result
    
    def _validate_urls(self, fields: Dict[str, Any]) -> ValidationResult:
        """Validate URL fields"""
        result = ValidationResult(valid=True, errors=[], warnings=[], field_validations={})
        
        url_fields = ["url.original", "url", "uri", "request_uri", "referrer", "http_referer"]
        
        for field in url_fields:
            if field in fields:
                url_value = str(fields[field])
                
                if url_value and url_value != "":
                    if self.patterns["url"].match(url_value):
                        result.field_validations[f"{field}_valid"] = True
                    else:
                        result.warnings.append(f"Possibly invalid URL: {url_value}")
                        result.field_validations[f"{field}_valid"] = False
        
        return result
    
    def _validate_email(self, fields: Dict[str, Any]) -> ValidationResult:
        """Validate email fields"""
        result = ValidationResult(valid=True, errors=[], warnings=[], field_validations={})
        
        email_fields = ["user.email", "email", "sender", "recipient", "from", "to"]
        
        for field in email_fields:
            if field in fields:
                email_value = str(fields[field])
                
                if email_value and email_value != "":
                    if self.patterns["email"].match(email_value):
                        result.field_validations[f"{field}_valid"] = True
                    else:
                        result.errors.append(f"Invalid email address: {email_value}")
                        result.valid = False
                        result.field_validations[f"{field}_valid"] = False
        
        return result
    
    def _validate_domains(self, fields: Dict[str, Any]) -> ValidationResult:
        """Validate domain fields"""
        result = ValidationResult(valid=True, errors=[], warnings=[], field_validations={})
        
        domain_fields = ["dns.question.name", "domain", "hostname", "host"]
        
        for field in domain_fields:
            if field in fields:
                domain_value = str(fields[field])
                
                if domain_value and domain_value != "":
                    if self.patterns["domain"].match(domain_value):
                        result.field_validations[f"{field}_valid"] = True
                    else:
                        result.warnings.append(f"Possibly invalid domain: {domain_value}")
                        result.field_validations[f"{field}_valid"] = False
        
        return result
    
    # ═══════════════════════════════════════════════════════════════════════════════
    # SECURITY-SPECIFIC VALIDATION
    # ═══════════════════════════════════════════════════════════════════════════════
    
    def _validate_user_names(self, fields: Dict[str, Any]) -> ValidationResult:
        """Validate user name fields"""
        result = ValidationResult(valid=True, errors=[], warnings=[], field_validations={})
        
        user_fields = ["user.name", "username", "account", "logon_user", "UserName"]
        
        for field in user_fields:
            if field in fields:
                username = str(fields[field])
                
                if username and username != "":
                    # Check for suspicious patterns
                    suspicious_patterns = ["admin", "administrator", "root", "sa", "system"]
                    if any(pattern in username.lower() for pattern in suspicious_patterns):
                        result.warnings.append(f"Privileged account detected: {username}")
                    
                    result.field_validations[f"{field}_valid"] = True
        
        return result
    
    def _validate_file_paths(self, fields: Dict[str, Any]) -> ValidationResult:
        """Validate file path fields"""
        result = ValidationResult(valid=True, errors=[], warnings=[], field_validations={})
        
        path_fields = ["file.path", "filepath", "filename", "ImageFileName", "TargetFilename"]
        
        for field in path_fields:
            if field in fields:
                path_value = str(fields[field])
                
                if path_value and path_value != "":
                    # Check path format
                    is_windows = self.patterns["windows_path"].match(path_value)
                    is_unix = self.patterns["unix_path"].match(path_value)
                    
                    if is_windows or is_unix:
                        result.field_validations[f"{field}_valid"] = True
                        
                        # Check for suspicious paths
                        suspicious_paths = [
                            "temp", "tmp", "appdata", "programdata", "system32", "syswow64"
                        ]
                        if any(suspicious in path_value.lower() for suspicious in suspicious_paths):
                            result.warnings.append(f"Suspicious file path: {path_value}")
                    else:
                        result.warnings.append(f"Unrecognized path format: {path_value}")
                        result.field_validations[f"{field}_valid"] = False
        
        return result
    
    def _validate_command_lines(self, fields: Dict[str, Any]) -> ValidationResult:
        """Validate command line fields"""
        result = ValidationResult(valid=True, errors=[], warnings=[], field_validations={})
        
        cmdline_fields = ["process.command_line", "CommandLine", "cmdline", "command"]
        
        for field in cmdline_fields:
            if field in fields:
                cmdline = str(fields[field])
                
                if cmdline and cmdline != "":
                    # Check for suspicious commands
                    suspicious_commands = [
                        "powershell", "cmd", "wscript", "cscript", "regsvr32", "rundll32",
                        "certutil", "bitsadmin", "wget", "curl", "nc", "netcat"
                    ]
                    
                    cmdline_lower = cmdline.lower()
                    for suspicious_cmd in suspicious_commands:
                        if suspicious_cmd in cmdline_lower:
                            result.warnings.append(f"Suspicious command detected: {suspicious_cmd}")
                    
                    # Check for obfuscation
                    if "base64" in cmdline_lower or "encoded" in cmdline_lower:
                        result.warnings.append("Possible command obfuscation detected")
                    
                    result.field_validations[f"{field}_valid"] = True
        
        return result
    
    def _validate_registry_keys(self, fields: Dict[str, Any]) -> ValidationResult:
        """Validate Windows registry key fields"""
        result = ValidationResult(valid=True, errors=[], warnings=[], field_validations={})
        
        registry_fields = ["registry.key", "RegKey", "RegistryKey", "reg_key"]
        
        for field in registry_fields:
            if field in fields:
                reg_key = str(fields[field])
                
                if reg_key and reg_key != "":
                    # Check for valid registry root
                    valid_roots = ["HKEY_", "HKLM", "HKCU", "HKU", "HKCR", "HKCC"]
                    has_valid_root = any(reg_key.upper().startswith(root) for root in valid_roots)
                    
                    if has_valid_root:
                        result.field_validations[f"{field}_valid"] = True
                        
                        # Check for sensitive registry locations
                        sensitive_keys = [
                            "run", "runonce", "winlogon", "services", "sam", "security",
                            "software\\microsoft\\windows\\currentversion\\run"
                        ]
                        if any(sensitive in reg_key.lower() for sensitive in sensitive_keys):
                            result.warnings.append(f"Sensitive registry key access: {reg_key}")
                    else:
                        result.warnings.append(f"Invalid registry key format: {reg_key}")
                        result.field_validations[f"{field}_valid"] = False
        
        return result
    
    # ═══════════════════════════════════════════════════════════════════════════════
    # NETWORK VALIDATION
    # ═══════════════════════════════════════════════════════════════════════════════
    
    def _validate_protocols(self, fields: Dict[str, Any]) -> ValidationResult:
        """Validate network protocol fields"""
        result = ValidationResult(valid=True, errors=[], warnings=[], field_validations={})
        
        protocol_fields = ["network.protocol", "protocol", "Protocol", "ip_protocol"]
        valid_protocols = ["TCP", "UDP", "ICMP", "IGMP", "GRE", "ESP", "AH", "SCTP"]
        
        for field in protocol_fields:
            if field in fields:
                protocol = str(fields[field]).upper()
                
                if protocol in valid_protocols:
                    result.field_validations[f"{field}_valid"] = True
                elif protocol.isdigit():
                    # Protocol number
                    proto_num = int(protocol)
                    if 0 <= proto_num <= 255:
                        result.field_validations[f"{field}_valid"] = True
                    else:
                        result.errors.append(f"Invalid protocol number: {proto_num}")
                        result.valid = False
                        result.field_validations[f"{field}_valid"] = False
                else:
                    result.warnings.append(f"Unknown protocol: {protocol}")
                    result.field_validations[f"{field}_valid"] = False
        
        return result
    
    def _validate_network_direction(self, fields: Dict[str, Any]) -> ValidationResult:
        """Validate network direction fields"""
        result = ValidationResult(valid=True, errors=[], warnings=[], field_validations={})
        
        direction_fields = ["network.direction", "direction", "ConnectionDirection"]
        valid_directions = ["inbound", "outbound", "internal", "external", "ingress", "egress"]
        
        for field in direction_fields:
            if field in fields:
                direction = str(fields[field]).lower()
                
                if direction in valid_directions:
                    result.field_validations[f"{field}_valid"] = True
                else:
                    result.warnings.append(f"Unknown network direction: {direction}")
                    result.field_validations[f"{field}_valid"] = False
        
        return result
    
    def _validate_geoip(self, fields: Dict[str, Any]) -> ValidationResult:
        """Validate GeoIP fields"""
        result = ValidationResult(valid=True, errors=[], warnings=[], field_validations={})
        
        # Country code validation
        country_fields = ["source.geo.country_iso_code", "destination.geo.country_iso_code"]
        for field in country_fields:
            if field in fields:
                country_code = str(fields[field])
                if len(country_code) == 2 and country_code.isalpha():
                    result.field_validations[f"{field}_valid"] = True
                else:
                    result.warnings.append(f"Invalid country code: {country_code}")
                    result.field_validations[f"{field}_valid"] = False
        
        # Coordinates validation
        lat_fields = ["source.geo.location.lat", "destination.geo.location.lat"]
        lon_fields = ["source.geo.location.lon", "destination.geo.location.lon"]
        
        for field in lat_fields:
            if field in fields:
                try:
                    lat = float(fields[field])
                    if -90 <= lat <= 90:
                        result.field_validations[f"{field}_valid"] = True
                    else:
                        result.errors.append(f"Invalid latitude: {lat}")
                        result.valid = False
                        result.field_validations[f"{field}_valid"] = False
                except (ValueError, TypeError):
                    result.errors.append(f"Invalid latitude format: {fields[field]}")
                    result.valid = False
                    result.field_validations[f"{field}_valid"] = False
        
        for field in lon_fields:
            if field in fields:
                try:
                    lon = float(fields[field])
                    if -180 <= lon <= 180:
                        result.field_validations[f"{field}_valid"] = True
                    else:
                        result.errors.append(f"Invalid longitude: {lon}")
                        result.valid = False
                        result.field_validations[f"{field}_valid"] = False
                except (ValueError, TypeError):
                    result.errors.append(f"Invalid longitude format: {fields[field]}")
                    result.valid = False
                    result.field_validations[f"{field}_valid"] = False
        
        return result
    
    # ═══════════════════════════════════════════════════════════════════════════════
    # AUTHENTICATION VALIDATION
    # ═══════════════════════════════════════════════════════════════════════════════
    
    def _validate_authentication(self, fields: Dict[str, Any]) -> ValidationResult:
        """Validate authentication fields"""
        result = ValidationResult(valid=True, errors=[], warnings=[], field_validations={})
        
        # Authentication outcome validation
        outcome_fields = ["event.outcome", "outcome", "result", "status"]
        valid_outcomes = ["success", "failure", "unknown", "pending"]
        
        for field in outcome_fields:
            if field in fields:
                outcome = str(fields[field]).lower()
                if outcome in valid_outcomes:
                    result.field_validations[f"{field}_valid"] = True
                else:
                    result.warnings.append(f"Unknown authentication outcome: {outcome}")
                    result.field_validations[f"{field}_valid"] = False
        
        # Logon type validation (Windows specific)
        if "authentication.logon_type" in fields:
            try:
                logon_type = int(fields["authentication.logon_type"])
                # Valid Windows logon types: 2, 3, 4, 5, 7, 8, 9, 10, 11
                valid_logon_types = [2, 3, 4, 5, 7, 8, 9, 10, 11]
                if logon_type in valid_logon_types:
                    result.field_validations["logon_type_valid"] = True
                else:
                    result.warnings.append(f"Unknown logon type: {logon_type}")
                    result.field_validations["logon_type_valid"] = False
            except (ValueError, TypeError):
                result.errors.append(f"Invalid logon type format: {fields['authentication.logon_type']}")
                result.valid = False
                result.field_validations["logon_type_valid"] = False
        
        return result
    
    def _validate_session_ids(self, fields: Dict[str, Any]) -> ValidationResult:
        """Validate session ID fields"""
        result = ValidationResult(valid=True, errors=[], warnings=[], field_validations={})
        
        session_fields = ["user.session.id", "session_id", "SessionId", "LogonId"]
        
        for field in session_fields:
            if field in fields:
                session_id = str(fields[field])
                
                if session_id and session_id != "":
                    # Check for valid session ID format (hex, GUID, or numeric)
                    if (self.patterns["session_id"].match(session_id) or 
                        self.patterns["guid"].match(session_id) or 
                        session_id.isdigit()):
                        result.field_validations[f"{field}_valid"] = True
                    else:
                        result.warnings.append(f"Unusual session ID format: {session_id}")
                        result.field_validations[f"{field}_valid"] = False
        
        return result
    
    # ═══════════════════════════════════════════════════════════════════════════════
    # THREAT INTELLIGENCE VALIDATION
    # ═══════════════════════════════════════════════════════════════════════════════
    
    def _validate_threat_indicators(self, fields: Dict[str, Any]) -> ValidationResult:
        """Validate threat indicator fields"""
        result = ValidationResult(valid=True, errors=[], warnings=[], field_validations={})
        
        # Check for malicious domains
        domain_fields = ["dns.question.name", "domain", "hostname"]
        for field in domain_fields:
            if field in fields:
                domain = str(fields[field]).lower()
                if domain in self.threat_indicators["malicious_domains"]:
                    result.warnings.append(f"Known malicious domain detected: {domain}")
        
        # Check for suspicious processes
        process_fields = ["process.name", "ImageFileName", "ProcessName"]
        for field in process_fields:
            if field in fields:
                process_name = str(fields[field]).lower()
                if any(suspicious in process_name for suspicious in self.threat_indicators["suspicious_processes"]):
                    result.warnings.append(f"Suspicious process detected: {process_name}")
        
        # Check for attack patterns in command lines
        cmdline_fields = ["process.command_line", "CommandLine"]
        for field in cmdline_fields:
            if field in fields:
                cmdline = str(fields[field]).lower()
                for pattern in self.threat_indicators["attack_patterns"]:
                    if pattern in cmdline:
                        result.warnings.append(f"Attack pattern detected: {pattern}")
        
        result.field_validations["threat_indicators_checked"] = True
        return result
    
    def _validate_mitre_techniques(self, fields: Dict[str, Any]) -> ValidationResult:
        """Validate MITRE ATT&CK technique fields"""
        result = ValidationResult(valid=True, errors=[], warnings=[], field_validations={})
        
        technique_fields = ["threat.technique.id", "mitre_technique", "TechniqueId", "technique_id"]
        
        for field in technique_fields:
            if field in fields:
                technique_id = str(fields[field]).upper()
                
                if technique_id in self.mitre_techniques:
                    result.field_validations[f"{field}_valid"] = True
                    result.warnings.append(f"MITRE technique detected: {technique_id} - {self.mitre_techniques[technique_id]}")
                else:
                    # Check if it's a valid technique format (T####)
                    if re.match(r'^T\d{4}$', technique_id):
                        result.warnings.append(f"Unknown MITRE technique: {technique_id}")
                        result.field_validations[f"{field}_valid"] = False
                    else:
                        result.errors.append(f"Invalid MITRE technique format: {technique_id}")
                        result.valid = False
                        result.field_validations[f"{field}_valid"] = False
        
        return result
    
    # ═══════════════════════════════════════════════════════════════════════════════
    # DATA CONSISTENCY VALIDATION
    # ═══════════════════════════════════════════════════════════════════════════════
    
    def _validate_process_hierarchy(self, fields: Dict[str, Any]) -> ValidationResult:
        """Validate process hierarchy consistency"""
        result = ValidationResult(valid=True, errors=[], warnings=[], field_validations={})
        
        # Check that parent PID is different from child PID
        if "process.pid" in fields and "process.parent.pid" in fields:
            try:
                child_pid = int(fields["process.pid"])
                parent_pid = int(fields["process.parent.pid"])
                
                if child_pid == parent_pid:
                    result.errors.append("Process PID cannot be same as parent PID")
                    result.valid = False
                elif parent_pid >= child_pid:
                    result.warnings.append("Parent PID is greater than or equal to child PID (unusual)")
                
                result.field_validations["process_hierarchy_valid"] = child_pid != parent_pid
            except (ValueError, TypeError):
                result.warnings.append("Invalid process ID values for hierarchy validation")
        
        return result
    
    def _validate_network_flow(self, fields: Dict[str, Any]) -> ValidationResult:
        """Validate network flow consistency"""
        result = ValidationResult(valid=True, errors=[], warnings=[], field_validations={})
        
        # Check source and destination are different
        if "source.ip" in fields and "destination.ip" in fields:
            src_ip = str(fields["source.ip"])
            dst_ip = str(fields["destination.ip"])
            
            if src_ip == dst_ip:
                result.warnings.append("Source and destination IP are the same")
                result.field_validations["network_flow_valid"] = False
            else:
                result.field_validations["network_flow_valid"] = True
        
        # Check port consistency with protocol
        if "network.protocol" in fields and "destination.port" in fields:
            protocol = str(fields["network.protocol"]).upper()
            try:
                dst_port = int(fields["destination.port"])
                
                # Check common protocol/port combinations
                if protocol == "TCP" and dst_port in [53, 67, 68, 69, 123, 161, 162]:
                    result.warnings.append(f"TCP on typically UDP port {dst_port}")
                elif protocol == "UDP" and dst_port in [20, 21, 22, 23, 25, 80, 110, 143, 443, 993, 995]:
                    result.warnings.append(f"UDP on typically TCP port {dst_port}")
                
                result.field_validations["protocol_port_consistent"] = True
            except (ValueError, TypeError):
                result.warnings.append("Invalid port number for protocol validation")
        
        return result
    
    def _validate_time_sequence(self, fields: Dict[str, Any]) -> ValidationResult:
        """Validate time sequence consistency"""
        result = ValidationResult(valid=True, errors=[], warnings=[], field_validations={})
        
        # Check that start time is before end time
        time_pairs = [
            ("process.start", "process.end"),
            ("event.start", "event.end"),
            ("session.start", "session.end")
        ]
        
        for start_field, end_field in time_pairs:
            if start_field in fields and end_field in fields:
                try:
                    start_time = datetime.fromisoformat(str(fields[start_field]).replace('Z', '+00:00'))
                    end_time = datetime.fromisoformat(str(fields[end_field]).replace('Z', '+00:00'))
                    
                    if start_time >= end_time:
                        result.errors.append(f"Start time ({start_field}) is not before end time ({end_field})")
                        result.valid = False
                        result.field_validations[f"{start_field}_{end_field}_sequence_valid"] = False
                    else:
                        result.field_validations[f"{start_field}_{end_field}_sequence_valid"] = True
                        
                        # Check for unreasonably long durations
                        duration = end_time - start_time
                        if duration.total_seconds() > 86400:  # 24 hours
                            result.warnings.append(f"Unusually long duration: {duration}")
                
                except (ValueError, TypeError):
                    result.warnings.append(f"Cannot parse timestamps for sequence validation: {start_field}, {end_field}")
        
        return result

# ═══════════════════════════════════════════════════════════════════════════════
# UTILITY FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

def validate_log_format_file(format_file_path: str) -> ValidationResult:
    """Validate a log format configuration file"""
    result = ValidationResult(valid=True, errors=[], warnings=[], field_validations={})
    
    try:
        format_path = Path(format_file_path)
        
        if not format_path.exists():
            result.valid = False
            result.errors.append(f"Format file does not exist: {format_file_path}")
            return result
        
        # Load format file
        with open(format_path, 'r') as f:
            if format_path.suffix.lower() == '.yaml' or format_path.suffix.lower() == '.yml':
                format_config = yaml.safe_load(f)
            elif format_path.suffix.lower() == '.json':
                format_config = json.load(f)
            else:
                result.valid = False
                result.errors.append(f"Unsupported format file type: {format_path.suffix}")
                return result
        
        # Validate required fields
        required_fields = ["name", "pattern_type", "field_mappings", "timestamp_field", "timestamp_format"]
        for field in required_fields:
            if field not in format_config:
                result.errors.append(f"Missing required field: {field}")
                result.valid = False
        
        # Validate pattern for regex types
        if format_config.get("pattern_type") == "regex" and "pattern" in format_config:
            try:
                re.compile(format_config["pattern"])
            except re.error as e:
                result.errors.append(f"Invalid regex pattern: {str(e)}")
                result.valid = False
        
        # Validate field mappings
        if "field_mappings" in format_config:
            if not isinstance(format_config["field_mappings"], dict):
                result.errors.append("field_mappings must be a dictionary")
                result.valid = False
        
        result.field_validations["format_file_valid"] = result.valid
        
    except Exception as e:
        result.valid = False
        result.errors.append(f"Error validating format file: {str(e)}")
    
    return result

def test_log_format(format_file_path: str, sample_logs: List[str]) -> Dict[str, ValidationResult]:
    """Test a log format against sample logs"""
    results = {}
    
    # First validate the format file
    format_validation = validate_log_format_file(format_file_path)
    results["format_file"] = format_validation
    
    if not format_validation.valid:
        return results
    
    # Load the format
    try:
        with open(format_file_path, 'r') as f:
            if format_file_path.endswith('.yaml') or format_file_path.endswith('.yml'):
                format_config = yaml.safe_load(f)
            else:
                format_config = json.load(f)
        
        validator = LogFormatValidator()
        validation_rules = format_config.get("validation_rules", [])
        
        # Test each sample log
        for i, sample_log in enumerate(sample_logs):
            # This is a simplified test - would need actual parsing logic
            sample_fields = {"raw_message": sample_log}
            result = validator.validate_parsed_log(sample_fields, validation_rules)
            results[f"sample_{i}"] = result
    
    except Exception as e:
        error_result = ValidationResult(valid=False, errors=[str(e)], warnings=[], field_validations={})
        results["test_error"] = error_result
    
    return results

if __name__ == "__main__":
    # Example usage
    validator = LogFormatValidator()
    
    # Test sample parsed log
    sample_fields = {
        "timestamp": "2024-01-15T10:30:45.123Z",
        "source.ip": "192.168.1.100",
        "destination.ip": "10.0.0.1",
        "source.port": 12345,
        "destination.port": 443,
        "event.action": "connection_attempt",
        "user.name": "admin",
        "process.pid": 1234,
        "process.parent.pid": 567,
        "file.hash.sha256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
    }
    
    validation_rules = [
        "require_timestamp",
        "require_source_ip",
        "validate_timestamp",
        "validate_ip_addresses",
        "validate_ports",
        "validate_process_ids",
        "validate_hashes",
        "validate_process_hierarchy"
    ]
    
    result = validator.validate_parsed_log(sample_fields, validation_rules)
    
    print("Validation Result:")
    print(f"Valid: {result.valid}")
    print(f"Errors: {result.errors}")
    print(f"Warnings: {result.warnings}")
    print(f"Field Validations: {result.field_validations}")