#!/usr/bin/env python3
"""
iSECTECH SIEM Sigma Rule Engine
Production-grade detection engine with Sigma rule support and MITRE ATT&CK integration
Implements advanced correlation logic and multi-source event correlation
"""

import asyncio
import json
import yaml
import logging
import time
import re
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Union, Set, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path
import aiofiles
from collections import defaultdict, deque
import hashlib
import fnmatch

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class SigmaRule:
    """Sigma detection rule"""
    rule_id: str
    title: str
    description: str
    author: str
    date: str
    level: str  # informational, low, medium, high, critical
    logsource: Dict[str, Any]
    detection: Dict[str, Any]
    fields: List[str]
    tags: List[str]
    references: List[str]
    falsepositives: List[str]
    mitre_attack: Dict[str, List[str]]
    custom_fields: Dict[str, Any]
    enabled: bool = True

@dataclass
class DetectionMatch:
    """Detection rule match result"""
    rule_id: str
    rule_title: str
    event_id: str
    timestamp: datetime
    matched_fields: Dict[str, Any]
    confidence_score: float
    severity: str
    mitre_tactics: List[str]
    mitre_techniques: List[str]
    raw_event: Dict[str, Any]
    correlation_id: str = ""
    parent_alerts: List[str] = None

@dataclass
class CorrelationRule:
    """Multi-event correlation rule"""
    rule_id: str
    name: str
    description: str
    conditions: List[Dict[str, Any]]
    timeframe: int  # seconds
    threshold: int
    group_by_fields: List[str]
    suppress_fields: List[str]
    severity: str
    enabled: bool = True

@dataclass
class CorrelationMatch:
    """Correlation rule match result"""
    rule_id: str
    rule_name: str
    events: List[DetectionMatch]
    correlation_key: str
    first_seen: datetime
    last_seen: datetime
    event_count: int
    confidence_score: float
    severity: str
    tactics: List[str]
    techniques: List[str]

class SigmaRuleEngine:
    """
    Production-grade Sigma rule engine for iSECTECH SIEM
    Supports standard Sigma rules with MITRE ATT&CK integration and correlation
    """
    
    def __init__(self, rules_directory: str, correlation_rules_file: str = ""):
        self.rules_directory = Path(rules_directory)
        self.correlation_rules_file = correlation_rules_file
        self.sigma_rules: Dict[str, SigmaRule] = {}
        self.correlation_rules: Dict[str, CorrelationRule] = {}
        
        # Event correlation state
        self.event_buffer: Dict[str, deque] = defaultdict(lambda: deque(maxlen=10000))
        self.correlation_state: Dict[str, Dict[str, Any]] = {}
        
        # Performance metrics
        self.stats = {
            "total_rules": 0,
            "enabled_rules": 0,
            "total_events_processed": 0,
            "total_matches": 0,
            "correlation_matches": 0,
            "avg_processing_time_ms": 0,
            "rule_performance": {}
        }
        
        # MITRE ATT&CK mapping
        self.attack_tactics = {}
        self.attack_techniques = {}
        
    async def initialize(self):
        """Initialize the Sigma rule engine"""
        try:
            # Load MITRE ATT&CK framework data
            await self._load_attack_framework()
            
            # Load Sigma rules
            await self._load_sigma_rules()
            
            # Load correlation rules
            if self.correlation_rules_file:
                await self._load_correlation_rules()
                
            logger.info(f"Sigma rule engine initialized with {len(self.sigma_rules)} rules")
            
        except Exception as e:
            logger.error(f"Failed to initialize Sigma rule engine: {e}")
            raise
            
    async def _load_attack_framework(self):
        """Load MITRE ATT&CK framework data"""
        try:
            # Create comprehensive MITRE ATT&CK mapping
            self.attack_tactics = {
                "TA0001": {
                    "name": "Initial Access",
                    "description": "Adversary is trying to get into your network"
                },
                "TA0002": {
                    "name": "Execution", 
                    "description": "Adversary is trying to run malicious code"
                },
                "TA0003": {
                    "name": "Persistence",
                    "description": "Adversary is trying to maintain their foothold"
                },
                "TA0004": {
                    "name": "Privilege Escalation",
                    "description": "Adversary is trying to gain higher-level permissions"
                },
                "TA0005": {
                    "name": "Defense Evasion",
                    "description": "Adversary is trying to avoid being detected"
                },
                "TA0006": {
                    "name": "Credential Access",
                    "description": "Adversary is trying to steal account names and passwords"
                },
                "TA0007": {
                    "name": "Discovery",
                    "description": "Adversary is trying to figure out your environment"
                },
                "TA0008": {
                    "name": "Lateral Movement",
                    "description": "Adversary is trying to move through your environment"
                },
                "TA0009": {
                    "name": "Collection",
                    "description": "Adversary is trying to gather data of interest"
                },
                "TA0010": {
                    "name": "Exfiltration",
                    "description": "Adversary is trying to steal data"
                },
                "TA0011": {
                    "name": "Command and Control",
                    "description": "Adversary is trying to communicate with compromised systems"
                },
                "TA0040": {
                    "name": "Impact",
                    "description": "Adversary is trying to manipulate, interrupt, or destroy systems and data"
                }
            }
            
            self.attack_techniques = {
                "T1059": {"name": "Command and Scripting Interpreter", "tactics": ["TA0002"]},
                "T1055": {"name": "Process Injection", "tactics": ["TA0004", "TA0005"]},
                "T1003": {"name": "OS Credential Dumping", "tactics": ["TA0006"]},
                "T1135": {"name": "Network Share Discovery", "tactics": ["TA0007"]},
                "T1021": {"name": "Remote Services", "tactics": ["TA0008"]},
                "T1071": {"name": "Application Layer Protocol", "tactics": ["TA0011"]},
                "T1053": {"name": "Scheduled Task/Job", "tactics": ["TA0002", "TA0003", "TA0004"]},
                "T1078": {"name": "Valid Accounts", "tactics": ["TA0001", "TA0003", "TA0004", "TA0008"]},
                "T1190": {"name": "Exploit Public-Facing Application", "tactics": ["TA0001"]},
                "T1566": {"name": "Phishing", "tactics": ["TA0001"]},
                "T1204": {"name": "User Execution", "tactics": ["TA0002"]},
                "T1543": {"name": "Create or Modify System Process", "tactics": ["TA0003", "TA0004"]},
                "T1562": {"name": "Impair Defenses", "tactics": ["TA0005"]},
                "T1070": {"name": "Indicator Removal on Host", "tactics": ["TA0005"]},
                "T1087": {"name": "Account Discovery", "tactics": ["TA0007"]},
                "T1083": {"name": "File and Directory Discovery", "tactics": ["TA0007"]},
                "T1082": {"name": "System Information Discovery", "tactics": ["TA0007"]},
                "T1005": {"name": "Data from Local System", "tactics": ["TA0009"]},
                "T1041": {"name": "Exfiltration Over C2 Channel", "tactics": ["TA0010"]},
                "T1486": {"name": "Data Encrypted for Impact", "tactics": ["TA0040"]},
                "T1491": {"name": "Defacement", "tactics": ["TA0040"]}
            }
            
            logger.info("Loaded MITRE ATT&CK framework data")
            
        except Exception as e:
            logger.error(f"Failed to load MITRE ATT&CK framework: {e}")
            
    async def _load_sigma_rules(self):
        """Load Sigma rules from directory"""
        try:
            if not self.rules_directory.exists():
                await self._create_default_rules()
                
            # Load all YAML files in rules directory
            for rule_file in self.rules_directory.rglob("*.yml"):
                try:
                    async with aiofiles.open(rule_file, 'r') as f:
                        content = await f.read()
                        rule_data = yaml.safe_load(content)
                        
                    # Parse Sigma rule
                    sigma_rule = await self._parse_sigma_rule(rule_data, rule_file.name)
                    if sigma_rule:
                        self.sigma_rules[sigma_rule.rule_id] = sigma_rule
                        
                except Exception as e:
                    logger.warning(f"Failed to load rule {rule_file}: {e}")
                    
            self.stats["total_rules"] = len(self.sigma_rules)
            self.stats["enabled_rules"] = len([r for r in self.sigma_rules.values() if r.enabled])
            
            logger.info(f"Loaded {len(self.sigma_rules)} Sigma rules")
            
        except Exception as e:
            logger.error(f"Failed to load Sigma rules: {e}")
            
    async def _create_default_rules(self):
        """Create default Sigma rules for common attack patterns"""
        self.rules_directory.mkdir(parents=True, exist_ok=True)
        
        # Create categories for rules
        categories = ["process_creation", "network", "authentication", "file_operations", "registry", "powershell"]
        
        for category in categories:
            category_dir = self.rules_directory / category
            category_dir.mkdir(exist_ok=True)
            
        # Sample Sigma rules
        default_rules = [
            {
                "filename": "process_creation/suspicious_powershell_execution.yml",
                "content": {
                    "title": "Suspicious PowerShell Execution",
                    "id": "e4b6d2a1-0b8c-4f3e-9d5f-1a2b3c4d5e6f",
                    "description": "Detects suspicious PowerShell command execution with encoded commands",
                    "author": "iSECTECH Security Team",
                    "date": "2024/01/15",
                    "level": "high",
                    "logsource": {
                        "category": "process_creation",
                        "product": "windows"
                    },
                    "detection": {
                        "selection": {
                            "process.name|endswith": "powershell.exe",
                            "process.command_line|contains": ["-EncodedCommand", "-enc", "-ExecutionPolicy Bypass"]
                        },
                        "condition": "selection"
                    },
                    "fields": ["process.name", "process.command_line", "user.name", "host.name"],
                    "tags": ["attack.execution", "attack.t1059.001"],
                    "references": ["https://attack.mitre.org/techniques/T1059/001/"],
                    "falsepositives": ["Legitimate administrative scripts"]
                }
            },
            {
                "filename": "authentication/multiple_failed_logins.yml",
                "content": {
                    "title": "Multiple Failed Login Attempts",
                    "id": "f5c7b8a9-2d1e-4a5b-8c3f-9e7d6a5b4c3d",
                    "description": "Detects multiple failed login attempts indicating potential brute force attack",
                    "author": "iSECTECH Security Team", 
                    "date": "2024/01/15",
                    "level": "medium",
                    "logsource": {
                        "category": "authentication",
                        "product": "windows"
                    },
                    "detection": {
                        "selection": {
                            "event.action": "login",
                            "event.outcome": "failure"
                        },
                        "timeframe": "5m",
                        "condition": "selection | count(source.ip) > 5"
                    },
                    "fields": ["user.name", "source.ip", "event.outcome"],
                    "tags": ["attack.credential_access", "attack.t1110"],
                    "references": ["https://attack.mitre.org/techniques/T1110/"],
                    "falsepositives": ["User typing errors", "Account lockout policies"]
                }
            },
            {
                "filename": "network/suspicious_outbound_connections.yml",
                "content": {
                    "title": "Suspicious Outbound Network Connections",
                    "id": "a3b5c7d9-4e6f-1a2b-8c5d-9f7e8a6b5c4d",
                    "description": "Detects outbound connections to suspicious destinations",
                    "author": "iSECTECH Security Team",
                    "date": "2024/01/15",
                    "level": "high",
                    "logsource": {
                        "category": "network_connection",
                        "product": "windows"
                    },
                    "detection": {
                        "selection": {
                            "event.action": "connection",
                            "network.direction": "outbound",
                            "destination.port": [80, 443, 8080, 8443]
                        },
                        "filter": {
                            "destination.domain|endswith": [".onion", ".bit"],
                            "destination.ip|startswith": ["10.", "172.16.", "192.168."]
                        },
                        "condition": "selection and not filter"
                    },
                    "fields": ["destination.ip", "destination.port", "process.name"],
                    "tags": ["attack.command_and_control", "attack.t1071"],
                    "references": ["https://attack.mitre.org/techniques/T1071/"],
                    "falsepositives": ["Legitimate business applications"]
                }
            },
            {
                "filename": "file_operations/ransomware_file_patterns.yml",
                "content": {
                    "title": "Ransomware File Extension Changes",
                    "id": "b4c6d8e0-5f7a-2b3c-9d6e-0f8a7b6c5d4e",
                    "description": "Detects file extension changes typical of ransomware encryption",
                    "author": "iSECTECH Security Team",
                    "date": "2024/01/15", 
                    "level": "critical",
                    "logsource": {
                        "category": "file_event",
                        "product": "windows"
                    },
                    "detection": {
                        "selection": {
                            "event.action": ["file_create", "file_rename"],
                            "file.extension": [".encrypted", ".locked", ".crypto", ".crypt", ".enc"]
                        },
                        "condition": "selection"
                    },
                    "fields": ["file.path", "file.name", "process.name", "user.name"],
                    "tags": ["attack.impact", "attack.t1486"],
                    "references": ["https://attack.mitre.org/techniques/T1486/"],
                    "falsepositives": ["Legitimate encryption software"]
                }
            },
            {
                "filename": "registry/persistence_registry_modifications.yml",
                "content": {
                    "title": "Registry Persistence Modifications",
                    "id": "c5d7e9f1-6a8b-3c4d-0e9f-1a7b8c6d5e4f",
                    "description": "Detects registry modifications for persistence mechanisms",
                    "author": "iSECTECH Security Team",
                    "date": "2024/01/15",
                    "level": "high",
                    "logsource": {
                        "category": "registry_event",
                        "product": "windows"
                    },
                    "detection": {
                        "selection": {
                            "event.action": "registry_set",
                            "registry.key|contains": [
                                "\\CurrentVersion\\Run\\",
                                "\\CurrentVersion\\RunOnce\\",
                                "\\Winlogon\\Shell",
                                "\\Winlogon\\Userinit"
                            ]
                        },
                        "condition": "selection"
                    },
                    "fields": ["registry.key", "registry.value", "process.name"],
                    "tags": ["attack.persistence", "attack.t1547.001"],
                    "references": ["https://attack.mitre.org/techniques/T1547/001/"],
                    "falsepositives": ["Software installations", "System updates"]
                }
            }
        ]
        
        # Write default rules to files
        for rule_def in default_rules:
            rule_path = self.rules_directory / rule_def["filename"]
            rule_path.parent.mkdir(parents=True, exist_ok=True)
            
            async with aiofiles.open(rule_path, 'w') as f:
                await f.write(yaml.dump(rule_def["content"], default_flow_style=False))
                
        logger.info(f"Created {len(default_rules)} default Sigma rules")
        
    async def _parse_sigma_rule(self, rule_data: Dict[str, Any], filename: str) -> Optional[SigmaRule]:
        """Parse a Sigma rule from YAML data"""
        try:
            # Extract MITRE ATT&CK tags
            tags = rule_data.get("tags", [])
            mitre_attack = {"tactics": [], "techniques": []}
            
            for tag in tags:
                if tag.startswith("attack."):
                    attack_ref = tag.replace("attack.", "").upper()
                    if attack_ref.startswith("T"):
                        mitre_attack["techniques"].append(attack_ref)
                    elif attack_ref.startswith("TA"):
                        mitre_attack["tactics"].append(attack_ref)
                    else:
                        # Map technique names to IDs
                        for tech_id, tech_data in self.attack_techniques.items():
                            if attack_ref.lower() in tech_data["name"].lower().replace(" ", "_"):
                                mitre_attack["techniques"].append(tech_id)
                                break
                                
            return SigmaRule(
                rule_id=rule_data.get("id", hashlib.md5(filename.encode()).hexdigest()),
                title=rule_data.get("title", "Unknown Rule"),
                description=rule_data.get("description", ""),
                author=rule_data.get("author", "Unknown"),
                date=rule_data.get("date", ""),
                level=rule_data.get("level", "medium"),
                logsource=rule_data.get("logsource", {}),
                detection=rule_data.get("detection", {}),
                fields=rule_data.get("fields", []),
                tags=tags,
                references=rule_data.get("references", []),
                falsepositives=rule_data.get("falsepositives", []),
                mitre_attack=mitre_attack,
                custom_fields=rule_data.get("custom", {}),
                enabled=rule_data.get("enabled", True)
            )
            
        except Exception as e:
            logger.error(f"Failed to parse Sigma rule {filename}: {e}")
            return None
            
    async def _load_correlation_rules(self):
        """Load correlation rules from configuration file"""
        try:
            if not Path(self.correlation_rules_file).exists():
                await self._create_default_correlation_rules()
                
            async with aiofiles.open(self.correlation_rules_file, 'r') as f:
                content = await f.read()
                config = yaml.safe_load(content)
                
            for rule_data in config.get("correlation_rules", []):
                correlation_rule = CorrelationRule(
                    rule_id=rule_data["rule_id"],
                    name=rule_data["name"],
                    description=rule_data["description"],
                    conditions=rule_data["conditions"],
                    timeframe=rule_data["timeframe"],
                    threshold=rule_data["threshold"],
                    group_by_fields=rule_data.get("group_by_fields", []),
                    suppress_fields=rule_data.get("suppress_fields", []),
                    severity=rule_data.get("severity", "medium"),
                    enabled=rule_data.get("enabled", True)
                )
                
                self.correlation_rules[correlation_rule.rule_id] = correlation_rule
                
            logger.info(f"Loaded {len(self.correlation_rules)} correlation rules")
            
        except Exception as e:
            logger.error(f"Failed to load correlation rules: {e}")
            
    async def _create_default_correlation_rules(self):
        """Create default correlation rules"""
        default_correlation_rules = {
            "correlation_rules": [
                {
                    "rule_id": "CORR-001",
                    "name": "Lateral Movement Detection",
                    "description": "Detects lateral movement through multiple failed and successful logins",
                    "conditions": [
                        {
                            "rule_tags": ["attack.credential_access"],
                            "event_type": "authentication"
                        },
                        {
                            "rule_tags": ["attack.lateral_movement"],
                            "event_type": "login"
                        }
                    ],
                    "timeframe": 3600,  # 1 hour
                    "threshold": 3,
                    "group_by_fields": ["user.name"],
                    "severity": "high",
                    "enabled": True
                },
                {
                    "rule_id": "CORR-002", 
                    "name": "Multi-Stage Attack Progression",
                    "description": "Detects progression through multiple attack stages",
                    "conditions": [
                        {
                            "rule_tags": ["attack.initial_access"],
                            "sequence": 1
                        },
                        {
                            "rule_tags": ["attack.execution"],
                            "sequence": 2
                        },
                        {
                            "rule_tags": ["attack.persistence"],
                            "sequence": 3
                        }
                    ],
                    "timeframe": 7200,  # 2 hours
                    "threshold": 1,
                    "group_by_fields": ["host.name", "user.name"],
                    "severity": "critical",
                    "enabled": True
                },
                {
                    "rule_id": "CORR-003",
                    "name": "Data Exfiltration Pattern",
                    "description": "Detects patterns indicating data collection and exfiltration",
                    "conditions": [
                        {
                            "rule_tags": ["attack.collection"],
                            "event_count": "> 10"
                        },
                        {
                            "rule_tags": ["attack.exfiltration"],
                            "network_bytes": "> 1000000"
                        }
                    ],
                    "timeframe": 1800,  # 30 minutes
                    "threshold": 1,
                    "group_by_fields": ["user.name", "source.ip"],
                    "severity": "critical",
                    "enabled": True
                }
            ]
        }
        
        # Create directory and save rules
        Path(self.correlation_rules_file).parent.mkdir(parents=True, exist_ok=True)
        async with aiofiles.open(self.correlation_rules_file, 'w') as f:
            await f.write(yaml.dump(default_correlation_rules, default_flow_style=False))
            
        logger.info("Created default correlation rules")
        
    async def process_event(self, event: Dict[str, Any]) -> List[DetectionMatch]:
        """Process a single event against all Sigma rules"""
        start_time = time.perf_counter()
        matches = []
        
        try:
            self.stats["total_events_processed"] += 1
            
            # Test event against each enabled Sigma rule
            for rule_id, rule in self.sigma_rules.items():
                if not rule.enabled:
                    continue
                    
                rule_start = time.perf_counter()
                
                if await self._test_rule_against_event(rule, event):
                    match = await self._create_detection_match(rule, event)
                    if match:
                        matches.append(match)
                        self.stats["total_matches"] += 1
                        
                # Track rule performance
                rule_time = (time.perf_counter() - rule_start) * 1000
                if rule_id not in self.stats["rule_performance"]:
                    self.stats["rule_performance"][rule_id] = {
                        "avg_time_ms": 0,
                        "execution_count": 0,
                        "match_count": 0
                    }
                    
                perf = self.stats["rule_performance"][rule_id]
                perf["execution_count"] += 1
                perf["avg_time_ms"] = (perf["avg_time_ms"] * (perf["execution_count"] - 1) + rule_time) / perf["execution_count"]
                
            # Update correlation state
            if matches:
                await self._update_correlation_state(matches)
                
        except Exception as e:
            logger.error(f"Error processing event: {e}")
            
        # Update performance statistics
        processing_time = (time.perf_counter() - start_time) * 1000
        current_avg = self.stats["avg_processing_time_ms"]
        count = self.stats["total_events_processed"]
        self.stats["avg_processing_time_ms"] = (current_avg * (count - 1) + processing_time) / count
        
        return matches
        
    async def _test_rule_against_event(self, rule: SigmaRule, event: Dict[str, Any]) -> bool:
        """Test if a Sigma rule matches against an event"""
        try:
            detection = rule.detection
            
            # Check logsource compatibility
            if not await self._check_logsource_match(rule.logsource, event):
                return False
                
            # Process detection logic
            condition = detection.get("condition", "")
            
            # Simple condition processing (production would need full Sigma parser)
            if "selection" in detection:
                selection_result = await self._evaluate_selection(detection["selection"], event)
                
                if condition == "selection":
                    return selection_result
                elif "not" in condition and "selection" in condition:
                    return not selection_result
                elif "|" in condition:  # OR condition
                    # Handle multiple selections
                    for key in detection:
                        if key.startswith("selection") and key != "selection":
                            if await self._evaluate_selection(detection[key], event):
                                return True
                    return selection_result
                elif "and" in condition:  # AND condition
                    # Check all selections
                    for key in detection:
                        if key.startswith("selection"):
                            if not await self._evaluate_selection(detection[key], event):
                                return False
                    return True
                    
            return False
            
        except Exception as e:
            logger.warning(f"Error testing rule {rule.rule_id}: {e}")
            return False
            
    async def _check_logsource_match(self, logsource: Dict[str, Any], event: Dict[str, Any]) -> bool:
        """Check if event matches rule logsource requirements"""
        # Simple logsource matching - production would be more sophisticated
        category = logsource.get("category", "")
        product = logsource.get("product", "")
        
        # Map event fields to logsource categories
        if category == "process_creation" and "process.name" in event:
            return True
        elif category == "authentication" and "event.action" in event and "login" in event["event.action"]:
            return True
        elif category == "network_connection" and "network" in str(event):
            return True
        elif category == "file_event" and "file" in str(event):
            return True
        elif category == "registry_event" and "registry" in str(event):
            return True
        elif not category:  # No specific category requirement
            return True
            
        return False
        
    async def _evaluate_selection(self, selection: Dict[str, Any], event: Dict[str, Any]) -> bool:
        """Evaluate a selection condition against an event"""
        try:
            for field_pattern, value_pattern in selection.items():
                # Handle field modifiers (e.g., field|contains, field|endswith)
                field_parts = field_pattern.split("|")
                field_name = field_parts[0]
                modifier = field_parts[1] if len(field_parts) > 1 else None
                
                # Get field value from event
                field_value = await self._get_field_value(event, field_name)
                if field_value is None:
                    return False
                    
                # Convert to string for pattern matching
                field_value_str = str(field_value).lower()
                
                # Handle different value patterns
                if isinstance(value_pattern, list):
                    # OR condition for list values
                    match_found = False
                    for pattern in value_pattern:
                        if await self._match_pattern(field_value_str, str(pattern).lower(), modifier):
                            match_found = True
                            break
                    if not match_found:
                        return False
                else:
                    # Single value pattern
                    if not await self._match_pattern(field_value_str, str(value_pattern).lower(), modifier):
                        return False
                        
            return True
            
        except Exception as e:
            logger.warning(f"Error evaluating selection: {e}")
            return False
            
    async def _get_field_value(self, event: Dict[str, Any], field_path: str) -> Any:
        """Get field value from event using dot notation"""
        try:
            current = event
            for part in field_path.split("."):
                if isinstance(current, dict) and part in current:
                    current = current[part]
                else:
                    return None
            return current
        except:
            return None
            
    async def _match_pattern(self, value: str, pattern: str, modifier: Optional[str]) -> bool:
        """Match value against pattern with optional modifier"""
        try:
            if modifier == "contains":
                return pattern in value
            elif modifier == "startswith":
                return value.startswith(pattern)
            elif modifier == "endswith":
                return value.endswith(pattern)
            elif modifier == "regex" or modifier == "re":
                return bool(re.search(pattern, value))
            elif modifier == "wildcard":
                return fnmatch.fnmatch(value, pattern)
            else:
                # Exact match
                return value == pattern
                
        except Exception as e:
            logger.warning(f"Error matching pattern {pattern} with modifier {modifier}: {e}")
            return False
            
    async def _create_detection_match(self, rule: SigmaRule, event: Dict[str, Any]) -> Optional[DetectionMatch]:
        """Create a detection match object"""
        try:
            # Extract matched fields
            matched_fields = {}
            for field in rule.fields:
                value = await self._get_field_value(event, field)
                if value is not None:
                    matched_fields[field] = value
                    
            # Calculate confidence score based on rule level and match quality
            confidence_scores = {
                "critical": 0.95,
                "high": 0.85,
                "medium": 0.70,
                "low": 0.55,
                "informational": 0.40
            }
            confidence = confidence_scores.get(rule.level, 0.70)
            
            # Adjust confidence based on matched fields
            if len(matched_fields) >= len(rule.fields) * 0.8:
                confidence += 0.05
                
            # Get MITRE tactics and techniques
            tactics = []
            techniques = []
            
            for tactic_id in rule.mitre_attack.get("tactics", []):
                if tactic_id in self.attack_tactics:
                    tactics.append(self.attack_tactics[tactic_id]["name"])
                    
            for technique_id in rule.mitre_attack.get("techniques", []):
                if technique_id in self.attack_techniques:
                    techniques.append(self.attack_techniques[technique_id]["name"])
                    
            return DetectionMatch(
                rule_id=rule.rule_id,
                rule_title=rule.title,
                event_id=event.get("event.id", ""),
                timestamp=datetime.now(timezone.utc),
                matched_fields=matched_fields,
                confidence_score=min(confidence, 1.0),
                severity=rule.level,
                mitre_tactics=tactics,
                mitre_techniques=techniques,
                raw_event=event.copy(),
                correlation_id=self._generate_correlation_id(event)
            )
            
        except Exception as e:
            logger.error(f"Error creating detection match: {e}")
            return None
            
    def _generate_correlation_id(self, event: Dict[str, Any]) -> str:
        """Generate correlation ID for event grouping"""
        # Use key fields to create correlation ID
        key_fields = [
            event.get("host.name", ""),
            event.get("user.name", ""),
            event.get("source.ip", ""),
            event.get("process.name", "")
        ]
        key_string = "|".join(str(f) for f in key_fields)
        return hashlib.md5(key_string.encode()).hexdigest()[:16]
        
    async def _update_correlation_state(self, matches: List[DetectionMatch]):
        """Update correlation state for multi-event detection"""
        try:
            current_time = datetime.now(timezone.utc)
            
            # Group matches by correlation ID
            for match in matches:
                corr_id = match.correlation_id
                
                # Add to event buffer
                self.event_buffer[corr_id].append({
                    "match": match,
                    "timestamp": current_time
                })
                
                # Clean old events from buffer
                cutoff_time = current_time - timedelta(hours=1)  # Keep 1 hour of events
                while (self.event_buffer[corr_id] and 
                       self.event_buffer[corr_id][0]["timestamp"] < cutoff_time):
                    self.event_buffer[corr_id].popleft()
                    
        except Exception as e:
            logger.error(f"Error updating correlation state: {e}")
            
    async def check_correlations(self) -> List[CorrelationMatch]:
        """Check for correlation rule matches"""
        correlation_matches = []
        
        try:
            current_time = datetime.now(timezone.utc)
            
            for rule_id, rule in self.correlation_rules.items():
                if not rule.enabled:
                    continue
                    
                matches = await self._evaluate_correlation_rule(rule, current_time)
                correlation_matches.extend(matches)
                
        except Exception as e:
            logger.error(f"Error checking correlations: {e}")
            
        return correlation_matches
        
    async def _evaluate_correlation_rule(self, rule: CorrelationRule, current_time: datetime) -> List[CorrelationMatch]:
        """Evaluate a single correlation rule"""
        matches = []
        
        try:
            timeframe_start = current_time - timedelta(seconds=rule.timeframe)
            
            # Group events by correlation fields
            event_groups = defaultdict(list)
            
            for corr_id, events in self.event_buffer.items():
                for event_data in events:
                    if event_data["timestamp"] >= timeframe_start:
                        # Check if event matches rule conditions
                        match_obj = event_data["match"]
                        
                        # Simple condition matching - production would be more sophisticated
                        for condition in rule.conditions:
                            rule_tags = condition.get("rule_tags", [])
                            if any(tag in match_obj.mitre_tactics + match_obj.mitre_techniques for tag in rule_tags):
                                # Generate grouping key
                                group_key = self._generate_group_key(match_obj.raw_event, rule.group_by_fields)
                                event_groups[group_key].append(match_obj)
                                break
                                
            # Check if any group meets threshold
            for group_key, group_events in event_groups.items():
                if len(group_events) >= rule.threshold:
                    # Create correlation match
                    correlation_match = CorrelationMatch(
                        rule_id=rule.rule_id,
                        rule_name=rule.name,
                        events=group_events,
                        correlation_key=group_key,
                        first_seen=min(event.timestamp for event in group_events),
                        last_seen=max(event.timestamp for event in group_events),
                        event_count=len(group_events),
                        confidence_score=min(sum(e.confidence_score for e in group_events) / len(group_events), 1.0),
                        severity=rule.severity,
                        tactics=list(set().union(*[e.mitre_tactics for e in group_events])),
                        techniques=list(set().union(*[e.mitre_techniques for e in group_events]))
                    )
                    
                    matches.append(correlation_match)
                    self.stats["correlation_matches"] += 1
                    
        except Exception as e:
            logger.error(f"Error evaluating correlation rule {rule.rule_id}: {e}")
            
        return matches
        
    def _generate_group_key(self, event: Dict[str, Any], group_fields: List[str]) -> str:
        """Generate grouping key from event fields"""
        key_parts = []
        for field in group_fields:
            value = event.get(field, "")
            key_parts.append(str(value))
        return "|".join(key_parts)
        
    async def get_statistics(self) -> Dict[str, Any]:
        """Get rule engine statistics"""
        return {
            **self.stats,
            "match_rate_percent": (self.stats["total_matches"] / max(self.stats["total_events_processed"], 1)) * 100,
            "top_performing_rules": sorted(
                [(rid, perf["avg_time_ms"]) for rid, perf in self.stats["rule_performance"].items()],
                key=lambda x: x[1]
            )[:10]
        }
        
    async def reload_rules(self):
        """Reload all Sigma rules from disk"""
        self.sigma_rules.clear()
        await self._load_sigma_rules()
        logger.info("Reloaded Sigma rules")
        
    async def cleanup(self):
        """Cleanup resources"""
        self.event_buffer.clear()
        self.correlation_state.clear()
        logger.info("Sigma rule engine cleanup completed")

# Example usage
async def main():
    """Example usage of Sigma rule engine"""
    rules_dir = "/opt/siem/detection/sigma_rules"
    correlation_file = "/opt/siem/detection/correlation_rules.yml"
    
    engine = SigmaRuleEngine(rules_dir, correlation_file)
    await engine.initialize()
    
    # Example security event
    test_event = {
        "@timestamp": "2024-01-15T10:30:00Z",
        "event.action": "process_creation",
        "host.name": "WORKSTATION01",
        "user.name": "admin",
        "process.name": "powershell.exe",
        "process.command_line": "powershell.exe -EncodedCommand SUVYIChHZXQtQ2hpbGRJdGVtIC1QYXRoICJDOlwiIC1SZWN1cnNlKQ==",
        "process.pid": 1234,
        "process.parent.name": "cmd.exe"
    }
    
    # Process event
    matches = await engine.process_event(test_event)
    
    print(f"Detection matches: {len(matches)}")
    for match in matches:
        print(f"  Rule: {match.rule_title}")
        print(f"  Severity: {match.severity}")
        print(f"  Confidence: {match.confidence_score:.2f}")
        print(f"  MITRE Tactics: {match.mitre_tactics}")
        print(f"  MITRE Techniques: {match.mitre_techniques}")
        print("---")
        
    # Check correlations
    correlations = await engine.check_correlations()
    print(f"Correlation matches: {len(correlations)}")
    
    # Get statistics
    stats = await engine.get_statistics()
    print(f"Statistics: {json.dumps(stats, indent=2)}")
    
    await engine.cleanup()

if __name__ == "__main__":
    asyncio.run(main())