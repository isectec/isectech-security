"""
Alert Normalizer - Standardizes alerts from multiple sources to Common Event Format (CEF)

Handles transformation of alerts from various security tools into a unified format
for consistent processing throughout the SOC automation platform.
"""

import re
import json
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
from enum import Enum
import structlog

logger = structlog.get_logger(__name__)

class AlertSeverity(Enum):
    """Standardized alert severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"

class AlertCategory(Enum):
    """Standardized alert categories based on MITRE ATT&CK"""
    RECONNAISSANCE = "reconnaissance"
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    EXFILTRATION = "exfiltration"
    COMMAND_AND_CONTROL = "command_and_control"
    IMPACT = "impact"
    MALWARE = "malware"
    NETWORK_ANOMALY = "network_anomaly"
    POLICY_VIOLATION = "policy_violation"
    SYSTEM_ANOMALY = "system_anomaly"

@dataclass
class NormalizedAlert:
    """Standardized alert structure"""
    # Core identification
    alert_id: str
    source: str
    source_type: str
    timestamp: datetime
    
    # Classification
    severity: AlertSeverity
    category: AlertCategory
    alert_type: str
    signature: str
    rule_id: Optional[str] = None
    
    # Network information
    source_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    
    # Asset information
    hostname: Optional[str] = None
    user: Optional[str] = None
    process: Optional[str] = None
    file_path: Optional[str] = None
    
    # Content
    description: str = ""
    details: Dict[str, Any] = None
    raw_data: Dict[str, Any] = None
    
    # Context
    mitre_tactics: List[str] = None
    mitre_techniques: List[str] = None
    tags: List[str] = None
    
    def __post_init__(self):
        if self.details is None:
            self.details = {}
        if self.raw_data is None:
            self.raw_data = {}
        if self.mitre_tactics is None:
            self.mitre_tactics = []
        if self.mitre_techniques is None:
            self.mitre_techniques = []
        if self.tags is None:
            self.tags = []

class AlertNormalizer:
    """
    Normalizes alerts from various security tools into standardized format.
    
    Supports:
    - SIEM platforms (Splunk, QRadar, ArcSight, Elastic Security)
    - EDR solutions (CrowdStrike, SentinelOne, Carbon Black)
    - Network security (Snort, Suricata, Zeek)
    - Cloud security (AWS CloudTrail, Azure Sentinel, GCP Security)
    - Custom sources via configurable parsers
    """
    
    def __init__(self):
        # Severity mapping from various sources
        self.severity_mappings = {
            'siem': {
                'critical': AlertSeverity.CRITICAL,
                'high': AlertSeverity.HIGH,
                'medium': AlertSeverity.MEDIUM,
                'low': AlertSeverity.LOW,
                'info': AlertSeverity.INFORMATIONAL,
                'informational': AlertSeverity.INFORMATIONAL,
                '1': AlertSeverity.CRITICAL,
                '2': AlertSeverity.HIGH,
                '3': AlertSeverity.MEDIUM,
                '4': AlertSeverity.LOW,
                '5': AlertSeverity.INFORMATIONAL
            },
            'edr': {
                'critical': AlertSeverity.CRITICAL,
                'high': AlertSeverity.HIGH,
                'medium': AlertSeverity.MEDIUM,
                'low': AlertSeverity.LOW,
                'informational': AlertSeverity.INFORMATIONAL
            },
            'network': {
                '1': AlertSeverity.CRITICAL,
                '2': AlertSeverity.HIGH,
                '3': AlertSeverity.MEDIUM,
                'critical': AlertSeverity.CRITICAL,
                'high': AlertSeverity.HIGH,
                'medium': AlertSeverity.MEDIUM,
                'low': AlertSeverity.LOW
            }
        }
        
        # Category mappings based on alert signatures/rules
        self.category_patterns = {
            AlertCategory.MALWARE: [
                r'malware', r'virus', r'trojan', r'ransomware', r'rootkit',
                r'backdoor', r'spyware', r'adware'
            ],
            AlertCategory.NETWORK_ANOMALY: [
                r'network.*anomaly', r'unusual.*traffic', r'port.*scan',
                r'ddos', r'brute.*force', r'flood'
            ],
            AlertCategory.PRIVILEGE_ESCALATION: [
                r'privilege.*escalation', r'elevation', r'admin.*access',
                r'root.*access', r'sudo', r'runas'
            ],
            AlertCategory.LATERAL_MOVEMENT: [
                r'lateral.*movement', r'pass.*the.*hash', r'wmi.*execution',
                r'remote.*execution', r'psexec'
            ],
            AlertCategory.CREDENTIAL_ACCESS: [
                r'credential.*access', r'password.*attack', r'hash.*dump',
                r'kerberos.*attack', r'ntlm'
            ],
            AlertCategory.EXFILTRATION: [
                r'data.*exfiltration', r'data.*transfer', r'large.*upload',
                r'suspicious.*download', r'file.*theft'
            ],
            AlertCategory.COMMAND_AND_CONTROL: [
                r'c2', r'command.*control', r'beacon', r'callback',
                r'suspicious.*dns', r'covert.*channel'
            ]
        }
        
        # MITRE ATT&CK mappings
        self.mitre_mappings = self._initialize_mitre_mappings()
        
        logger.info("AlertNormalizer initialized with pattern mappings")
    
    async def normalize(self, raw_alert: Dict[str, Any], source: str) -> Optional[Dict[str, Any]]:
        """
        Normalize a raw alert to standardized format
        
        Args:
            raw_alert: Raw alert data from source
            source: Source identifier/type
            
        Returns:
            Normalized alert dictionary or None if normalization fails
        """
        try:
            # Detect source type and apply appropriate normalization
            source_type = self._detect_source_type(raw_alert, source)
            
            if source_type == 'splunk':
                normalized = await self._normalize_splunk(raw_alert, source)
            elif source_type == 'elastic':
                normalized = await self._normalize_elastic(raw_alert, source)
            elif source_type == 'crowdstrike':
                normalized = await self._normalize_crowdstrike(raw_alert, source)
            elif source_type == 'suricata':
                normalized = await self._normalize_suricata(raw_alert, source)
            elif source_type == 'cloudtrail':
                normalized = await self._normalize_cloudtrail(raw_alert, source)
            elif source_type == 'custom':
                normalized = await self._normalize_custom(raw_alert, source)
            else:
                # Fallback to generic normalization
                normalized = await self._normalize_generic(raw_alert, source)
            
            if normalized:
                # Post-processing: add MITRE mappings and enrichment
                self._add_mitre_mappings(normalized)
                self._add_context_tags(normalized)
                
                logger.debug("Alert normalized successfully",
                           alert_id=normalized.get('alert_id'),
                           source_type=source_type,
                           category=normalized.get('category'))
                
                return normalized
            
            logger.warning("Alert normalization produced no result", source=source)
            return None
            
        except Exception as e:
            logger.error("Alert normalization failed", source=source, error=str(e))
            return None
    
    def _detect_source_type(self, alert: Dict[str, Any], source: str) -> str:
        """Detect the type of security tool that generated the alert"""
        source_lower = source.lower()
        
        # Direct source type mapping
        if 'splunk' in source_lower:
            return 'splunk'
        elif 'elastic' in source_lower or 'kibana' in source_lower:
            return 'elastic'
        elif 'crowdstrike' in source_lower:
            return 'crowdstrike'
        elif 'suricata' in source_lower or 'snort' in source_lower:
            return 'suricata'
        elif 'cloudtrail' in source_lower or 'aws' in source_lower:
            return 'cloudtrail'
        
        # Detection based on alert structure
        if 'search_name' in alert or 'result' in alert:
            return 'splunk'
        elif '@timestamp' in alert and 'event' in alert:
            return 'elastic'
        elif 'detection_id' in alert and 'severity' in alert:
            return 'crowdstrike'
        elif 'alert' in alert and 'flow_id' in alert:
            return 'suricata'
        elif 'eventSource' in alert and 'awsRegion' in alert:
            return 'cloudtrail'
        
        return 'custom'
    
    async def _normalize_splunk(self, alert: Dict[str, Any], source: str) -> Dict[str, Any]:
        """Normalize Splunk alerts"""
        result = alert.get('result', {})
        
        return {
            'alert_id': alert.get('sid', self._generate_id()),
            'source': source,
            'source_type': 'splunk',
            'timestamp': self._parse_timestamp(result.get('_time', result.get('timestamp'))),
            'severity': self._normalize_severity(result.get('urgency', 'medium'), 'siem'),
            'category': self._categorize_alert(result.get('search_name', '')),
            'alert_type': result.get('search_name', 'Unknown'),
            'signature': result.get('signature', result.get('search_name', 'Unknown')),
            'rule_id': result.get('savedsearch_id'),
            'source_ip': result.get('src_ip', result.get('src')),
            'destination_ip': result.get('dest_ip', result.get('dest')),
            'hostname': result.get('host', result.get('src_host')),
            'user': result.get('user', result.get('src_user')),
            'description': result.get('_raw', ''),
            'details': result,
            'raw_data': alert
        }
    
    async def _normalize_elastic(self, alert: Dict[str, Any], source: str) -> Dict[str, Any]:
        """Normalize Elastic Security alerts"""
        event = alert.get('event', {})
        source_data = alert.get('source', {})
        dest_data = alert.get('destination', {})
        
        return {
            'alert_id': alert.get('_id', self._generate_id()),
            'source': source,
            'source_type': 'elastic',
            'timestamp': self._parse_timestamp(alert.get('@timestamp')),
            'severity': self._normalize_severity(event.get('severity', 'medium'), 'siem'),
            'category': self._categorize_alert(event.get('category', '')),
            'alert_type': event.get('type', 'Unknown'),
            'signature': alert.get('rule', {}).get('name', 'Unknown'),
            'rule_id': alert.get('rule', {}).get('id'),
            'source_ip': source_data.get('ip'),
            'source_port': source_data.get('port'),
            'destination_ip': dest_data.get('ip'),
            'destination_port': dest_data.get('port'),
            'hostname': alert.get('host', {}).get('name'),
            'user': alert.get('user', {}).get('name'),
            'process': alert.get('process', {}).get('name'),
            'description': event.get('original', ''),
            'details': event,
            'raw_data': alert
        }
    
    async def _normalize_crowdstrike(self, alert: Dict[str, Any], source: str) -> Dict[str, Any]:
        """Normalize CrowdStrike Falcon alerts"""
        return {
            'alert_id': alert.get('detection_id', self._generate_id()),
            'source': source,
            'source_type': 'crowdstrike',
            'timestamp': self._parse_timestamp(alert.get('created_timestamp')),
            'severity': self._normalize_severity(alert.get('max_severity_displayname', 'medium'), 'edr'),
            'category': self._categorize_alert(alert.get('tactic', '')),
            'alert_type': alert.get('technique', 'Unknown'),
            'signature': alert.get('description', 'Unknown'),
            'rule_id': alert.get('pattern_id'),
            'source_ip': alert.get('device', {}).get('local_ip'),
            'hostname': alert.get('device', {}).get('hostname'),
            'user': alert.get('user_name'),
            'process': alert.get('parent_details', {}).get('parent_process'),
            'file_path': alert.get('filepath'),
            'description': alert.get('description', ''),
            'details': alert.get('behaviors', []),
            'raw_data': alert
        }
    
    async def _normalize_suricata(self, alert: Dict[str, Any], source: str) -> Dict[str, Any]:
        """Normalize Suricata/Snort IDS alerts"""
        alert_data = alert.get('alert', {})
        
        return {
            'alert_id': str(alert.get('flow_id', self._generate_id())),
            'source': source,
            'source_type': 'suricata',
            'timestamp': self._parse_timestamp(alert.get('timestamp')),
            'severity': self._normalize_severity(alert_data.get('severity', '3'), 'network'),
            'category': self._categorize_alert(alert_data.get('category', '')),
            'alert_type': alert_data.get('signature', 'Unknown'),
            'signature': alert_data.get('signature', 'Unknown'),
            'rule_id': str(alert_data.get('signature_id')),
            'source_ip': alert.get('src_ip'),
            'source_port': alert.get('src_port'),
            'destination_ip': alert.get('dest_ip'),
            'destination_port': alert.get('dest_port'),
            'protocol': alert.get('proto'),
            'description': alert_data.get('signature', ''),
            'details': alert_data,
            'raw_data': alert
        }
    
    async def _normalize_cloudtrail(self, alert: Dict[str, Any], source: str) -> Dict[str, Any]:
        """Normalize AWS CloudTrail events"""
        return {
            'alert_id': alert.get('eventID', self._generate_id()),
            'source': source,
            'source_type': 'cloudtrail',
            'timestamp': self._parse_timestamp(alert.get('eventTime')),
            'severity': self._normalize_severity('medium', 'siem'),  # Default for CloudTrail
            'category': self._categorize_alert(alert.get('eventName', '')),
            'alert_type': alert.get('eventName', 'Unknown'),
            'signature': f"{alert.get('eventSource')}:{alert.get('eventName')}",
            'source_ip': alert.get('sourceIPAddress'),
            'user': alert.get('userIdentity', {}).get('userName', 
                             alert.get('userIdentity', {}).get('arn')),
            'description': f"AWS {alert.get('eventName')} by {alert.get('userIdentity', {}).get('type')}",
            'details': alert.get('requestParameters', {}),
            'raw_data': alert
        }
    
    async def _normalize_custom(self, alert: Dict[str, Any], source: str) -> Dict[str, Any]:
        """Normalize custom/generic alerts"""
        return await self._normalize_generic(alert, source)
    
    async def _normalize_generic(self, alert: Dict[str, Any], source: str) -> Dict[str, Any]:
        """Generic normalization for unknown sources"""
        return {
            'alert_id': alert.get('id', alert.get('alert_id', self._generate_id())),
            'source': source,
            'source_type': 'generic',
            'timestamp': self._parse_timestamp(
                alert.get('timestamp', alert.get('@timestamp', alert.get('time')))
            ),
            'severity': self._normalize_severity(
                alert.get('severity', alert.get('level', 'medium')), 'siem'
            ),
            'category': self._categorize_alert(
                alert.get('category', alert.get('type', ''))
            ),
            'alert_type': alert.get('type', alert.get('event_type', 'Unknown')),
            'signature': alert.get('signature', alert.get('message', 'Unknown')),
            'rule_id': alert.get('rule_id', alert.get('rule')),
            'source_ip': alert.get('source_ip', alert.get('src_ip')),
            'destination_ip': alert.get('destination_ip', alert.get('dest_ip')),
            'hostname': alert.get('hostname', alert.get('host')),
            'user': alert.get('user', alert.get('username')),
            'description': alert.get('message', alert.get('description', '')),
            'details': {k: v for k, v in alert.items() 
                       if k not in ['id', 'timestamp', 'severity']},
            'raw_data': alert
        }
    
    def _normalize_severity(self, severity: Any, source_type: str) -> AlertSeverity:
        """Normalize severity to standard levels"""
        if severity is None:
            return AlertSeverity.MEDIUM
        
        severity_str = str(severity).lower().strip()
        mapping = self.severity_mappings.get(source_type, self.severity_mappings['siem'])
        
        return mapping.get(severity_str, AlertSeverity.MEDIUM)
    
    def _categorize_alert(self, alert_info: str) -> AlertCategory:
        """Categorize alert based on signature/type using pattern matching"""
        if not alert_info:
            return AlertCategory.SYSTEM_ANOMALY
        
        alert_lower = alert_info.lower()
        
        for category, patterns in self.category_patterns.items():
            for pattern in patterns:
                if re.search(pattern, alert_lower):
                    return category
        
        return AlertCategory.SYSTEM_ANOMALY
    
    def _parse_timestamp(self, timestamp: Any) -> datetime:
        """Parse timestamp from various formats"""
        if timestamp is None:
            return datetime.now(timezone.utc)
        
        if isinstance(timestamp, datetime):
            return timestamp.replace(tzinfo=timezone.utc) if timestamp.tzinfo is None else timestamp
        
        if isinstance(timestamp, (int, float)):
            # Unix timestamp
            if timestamp > 1e10:  # Milliseconds
                timestamp = timestamp / 1000
            return datetime.fromtimestamp(timestamp, tz=timezone.utc)
        
        if isinstance(timestamp, str):
            # Try common formats
            formats = [
                '%Y-%m-%dT%H:%M:%S.%fZ',
                '%Y-%m-%dT%H:%M:%SZ',
                '%Y-%m-%dT%H:%M:%S',
                '%Y-%m-%d %H:%M:%S.%f',
                '%Y-%m-%d %H:%M:%S',
                '%m/%d/%Y %H:%M:%S',
                '%d/%m/%Y %H:%M:%S'
            ]
            
            for fmt in formats:
                try:
                    dt = datetime.strptime(timestamp, fmt)
                    return dt.replace(tzinfo=timezone.utc)
                except ValueError:
                    continue
        
        # Fallback to current time
        logger.warning("Could not parse timestamp, using current time", timestamp=timestamp)
        return datetime.now(timezone.utc)
    
    def _add_mitre_mappings(self, alert: Dict[str, Any]):
        """Add MITRE ATT&CK tactics and techniques"""
        category = alert.get('category')
        alert_type = alert.get('alert_type', '').lower()
        signature = alert.get('signature', '').lower()
        
        # Map categories to MITRE tactics
        tactic_mapping = {
            AlertCategory.RECONNAISSANCE: ['TA0043'],
            AlertCategory.INITIAL_ACCESS: ['TA0001'],
            AlertCategory.EXECUTION: ['TA0002'],
            AlertCategory.PERSISTENCE: ['TA0003'],
            AlertCategory.PRIVILEGE_ESCALATION: ['TA0004'],
            AlertCategory.DEFENSE_EVASION: ['TA0005'],
            AlertCategory.CREDENTIAL_ACCESS: ['TA0006'],
            AlertCategory.DISCOVERY: ['TA0007'],
            AlertCategory.LATERAL_MOVEMENT: ['TA0008'],
            AlertCategory.COLLECTION: ['TA0009'],
            AlertCategory.EXFILTRATION: ['TA0010'],
            AlertCategory.COMMAND_AND_CONTROL: ['TA0011'],
            AlertCategory.IMPACT: ['TA0040']
        }
        
        if isinstance(category, AlertCategory):
            alert['mitre_tactics'] = tactic_mapping.get(category, [])
        
        # Add techniques based on signature patterns
        techniques = []
        for pattern, technique_id in self.mitre_mappings.items():
            if re.search(pattern, f"{alert_type} {signature}"):
                techniques.append(technique_id)
        
        alert['mitre_techniques'] = techniques
    
    def _add_context_tags(self, alert: Dict[str, Any]):
        """Add contextual tags based on alert content"""
        tags = set()
        
        # Add severity-based tags
        if alert.get('severity') == AlertSeverity.CRITICAL:
            tags.add('high_priority')
        
        # Add network-based tags
        if alert.get('source_ip'):
            if self._is_private_ip(alert['source_ip']):
                tags.add('internal_source')
            else:
                tags.add('external_source')
        
        # Add time-based tags
        hour = alert.get('timestamp').hour if alert.get('timestamp') else 0
        if hour < 6 or hour > 22:
            tags.add('after_hours')
        
        # Add category-based tags
        category = alert.get('category')
        if category in [AlertCategory.MALWARE, AlertCategory.RANSOMWARE]:
            tags.add('malicious_activity')
        
        alert['tags'] = list(tags)
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP address is in private range"""
        try:
            import ipaddress
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except ValueError:
            return False
    
    def _generate_id(self) -> str:
        """Generate unique alert ID"""
        import uuid
        return str(uuid.uuid4())
    
    def _initialize_mitre_mappings(self) -> Dict[str, str]:
        """Initialize MITRE ATT&CK technique mappings"""
        return {
            r'brute.*force': 'T1110',
            r'password.*spray': 'T1110.003',
            r'credential.*dump': 'T1003',
            r'pass.*the.*hash': 'T1550.002',
            r'kerberoasting': 'T1558.003',
            r'golden.*ticket': 'T1558.001',
            r'privilege.*escalation': 'T1068',
            r'dll.*injection': 'T1055.001',
            r'process.*hollowing': 'T1055.012',
            r'powershell': 'T1059.001',
            r'command.*line': 'T1059.003',
            r'wmi.*execution': 'T1047',
            r'scheduled.*task': 'T1053.005',
            r'registry.*run': 'T1547.001',
            r'startup.*folder': 'T1547.001',
            r'lateral.*movement': 'T1021',
            r'remote.*desktop': 'T1021.001',
            r'psexec': 'T1021.002',
            r'web.*shell': 'T1505.003',
            r'data.*exfiltration': 'T1041',
            r'dns.*tunneling': 'T1071.004',
            r'https.*tunnel': 'T1071.001',
            r'port.*scan': 'T1046',
            r'network.*discovery': 'T1018'
        }