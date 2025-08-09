"""
Security Response and Remediation Engine for ISECTECH Email Security Integration

This module provides comprehensive security incident response including:
- Automated incident creation and classification
- Post-delivery email remediation and recall
- Security alert generation and escalation
- Threat hunting and retroactive analysis
- Integration with SIEM/SOAR platforms
- Production-grade incident management workflow

Author: ISECTECH Security Team
Version: 1.0.0
"""

import asyncio
import json
import logging
import sqlite3
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Set, Union
from dataclasses import dataclass, asdict
from enum import Enum
import hashlib
import aiohttp
from email.message import EmailMessage

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class IncidentSeverity(Enum):
    """Security incident severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class IncidentStatus(Enum):
    """Incident lifecycle status"""
    NEW = "new"
    INVESTIGATING = "investigating"
    CONFIRMED = "confirmed"
    CONTAINED = "contained"
    ERADICATED = "eradicated"
    RECOVERED = "recovered"
    CLOSED = "closed"
    FALSE_POSITIVE = "false_positive"


class ThreatType(Enum):
    """Types of email security threats"""
    PHISHING = "phishing"
    MALWARE = "malware"
    RANSOMWARE = "ransomware"
    BEC = "business_email_compromise"
    SPAM = "spam"
    DATA_EXFILTRATION = "data_exfiltration"
    CREDENTIAL_HARVESTING = "credential_harvesting"
    SOCIAL_ENGINEERING = "social_engineering"
    INSIDER_THREAT = "insider_threat"
    APT = "advanced_persistent_threat"


class RemediationAction(Enum):
    """Available remediation actions"""
    RECALL_EMAIL = "recall_email"
    QUARANTINE_EMAIL = "quarantine_email"
    DELETE_EMAIL = "delete_email"
    MOVE_TO_JUNK = "move_to_junk"
    DISABLE_LINKS = "disable_links"
    BLOCK_SENDER = "block_sender"
    ADD_SAFE_SENDER = "add_safe_sender"
    NOTIFY_USERS = "notify_users"
    RESET_PASSWORDS = "reset_passwords"
    BLOCK_DOMAIN = "block_domain"
    CREATE_TRANSPORT_RULE = "create_transport_rule"


class AlertChannel(Enum):
    """Alert notification channels"""
    EMAIL = "email"
    SLACK = "slack"
    TEAMS = "teams"
    WEBHOOK = "webhook"
    SIEM = "siem"
    SOAR = "soar"
    SMS = "sms"
    DASHBOARD = "dashboard"


@dataclass
class ThreatIndicator:
    """Security threat indicator"""
    indicator_type: str
    value: str
    confidence: float
    severity: IncidentSeverity
    description: str
    source: str
    created_timestamp: datetime
    ttl_hours: Optional[int] = None


@dataclass
class SecurityIncident:
    """Security incident data structure"""
    incident_id: str
    title: str
    description: str
    severity: IncidentSeverity
    status: IncidentStatus
    threat_type: ThreatType
    affected_users: List[str]
    affected_emails: List[str]
    indicators: List[ThreatIndicator]
    created_timestamp: datetime
    updated_timestamp: datetime
    assigned_to: Optional[str]
    escalation_level: int
    remediation_actions: List[str]
    timeline: List[Dict[str, Any]]
    false_positive_likelihood: float
    impact_assessment: Dict[str, Any]


@dataclass
class RemediationTask:
    """Remediation task definition"""
    task_id: str
    incident_id: str
    action: RemediationAction
    target_emails: List[str]
    target_users: List[str]
    parameters: Dict[str, Any]
    priority: int
    estimated_duration: int  # minutes
    dependencies: List[str]
    status: str
    created_timestamp: datetime
    scheduled_timestamp: Optional[datetime]
    completed_timestamp: Optional[datetime]
    success: Optional[bool]
    error_message: Optional[str]


@dataclass
class AlertNotification:
    """Security alert notification"""
    alert_id: str
    incident_id: str
    channel: AlertChannel
    recipients: List[str]
    subject: str
    message: str
    urgency: str
    sent_timestamp: Optional[datetime]
    delivery_status: str
    retry_count: int


@dataclass
class HuntingQuery:
    """Threat hunting query definition"""
    query_id: str
    name: str
    description: str
    query_logic: str
    threat_types: List[ThreatType]
    lookback_hours: int
    enabled: bool
    last_run: Optional[datetime]
    hit_count: int
    false_positive_rate: float


class SecurityResponseEngine:
    """
    Advanced security response and remediation engine
    
    Provides automated incident response, threat hunting, and remediation
    capabilities for email security threats with SIEM/SOAR integration.
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        """Initialize security response engine"""
        self.config = config or self._get_default_config()
        self.data_dir = Path(self.config.get('data_directory', '/tmp/security_response'))
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize components
        self.active_incidents: Dict[str, SecurityIncident] = {}
        self.remediation_queue: List[RemediationTask] = []
        self.hunting_queries: Dict[str, HuntingQuery] = {}
        
        # HTTP session for external integrations
        self.session: Optional[aiohttp.ClientSession] = None
        
        # Initialize database
        self._init_database()
        
        # Load hunting queries
        self._load_hunting_queries()
        
        # Performance tracking
        self.response_stats = {
            'total_incidents': 0,
            'incidents_by_severity': {},
            'mean_response_time': 0.0,
            'remediation_success_rate': 0.0,
            'false_positive_rate': 0.0
        }
        
        logger.info("Security Response Engine initialized")
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration"""
        return {
            'data_directory': '/tmp/security_response',
            'auto_escalation_enabled': True,
            'escalation_thresholds': {
                'critical': 15,  # minutes
                'high': 30,
                'medium': 60,
                'low': 240
            },
            'auto_remediation_enabled': True,
            'remediation_approval_required': {
                'critical': False,
                'high': True,
                'medium': True,
                'low': False
            },
            'notification_channels': {
                'critical': ['email', 'siem', 'teams'],
                'high': ['email', 'siem'],
                'medium': ['email'],
                'low': ['dashboard']
            },
            'threat_hunting_interval': 300,  # 5 minutes
            'incident_retention_days': 90,
            'max_concurrent_remediations': 50,
            'siem_integration_enabled': True,
            'soar_integration_enabled': False
        }
    
    def _init_database(self):
        """Initialize SQLite database for incident management"""
        db_path = self.data_dir / 'security_response.db'
        self.db_connection = sqlite3.connect(str(db_path), check_same_thread=False)
        
        self.db_connection.execute('''
            CREATE TABLE IF NOT EXISTS incidents (
                incident_id TEXT PRIMARY KEY,
                title TEXT,
                description TEXT,
                severity TEXT,
                status TEXT,
                threat_type TEXT,
                affected_users TEXT,
                affected_emails TEXT,
                created_timestamp REAL,
                updated_timestamp REAL,
                assigned_to TEXT,
                escalation_level INTEGER,
                false_positive_likelihood REAL,
                impact_assessment TEXT
            )
        ''')
        
        self.db_connection.execute('''
            CREATE TABLE IF NOT EXISTS remediation_tasks (
                task_id TEXT PRIMARY KEY,
                incident_id TEXT,
                action TEXT,
                target_emails TEXT,
                target_users TEXT,
                parameters TEXT,
                priority INTEGER,
                status TEXT,
                created_timestamp REAL,
                scheduled_timestamp REAL,
                completed_timestamp REAL,
                success BOOLEAN,
                error_message TEXT,
                FOREIGN KEY (incident_id) REFERENCES incidents (incident_id)
            )
        ''')
        
        self.db_connection.execute('''
            CREATE TABLE IF NOT EXISTS threat_indicators (
                indicator_id TEXT PRIMARY KEY,
                incident_id TEXT,
                indicator_type TEXT,
                value TEXT,
                confidence REAL,
                severity TEXT,
                description TEXT,
                source TEXT,
                created_timestamp REAL,
                ttl_hours INTEGER,
                FOREIGN KEY (incident_id) REFERENCES incidents (incident_id)
            )
        ''')
        
        self.db_connection.execute('''
            CREATE TABLE IF NOT EXISTS alert_notifications (
                alert_id TEXT PRIMARY KEY,
                incident_id TEXT,
                channel TEXT,
                recipients TEXT,
                subject TEXT,
                message TEXT,
                urgency TEXT,
                sent_timestamp REAL,
                delivery_status TEXT,
                retry_count INTEGER,
                FOREIGN KEY (incident_id) REFERENCES incidents (incident_id)
            )
        ''')
        
        self.db_connection.execute('''
            CREATE TABLE IF NOT EXISTS hunting_results (
                result_id TEXT PRIMARY KEY,
                query_id TEXT,
                execution_timestamp REAL,
                hit_count INTEGER,
                results TEXT,
                processing_time REAL
            )
        ''')
        
        self.db_connection.commit()
    
    def _load_hunting_queries(self):
        """Load predefined threat hunting queries"""
        # Email-based threat hunting queries
        queries = [
            HuntingQuery(
                query_id="suspicious_sender_volume",
                name="Suspicious Sender Volume",
                description="Detect senders with unusually high email volume",
                query_logic="SELECT sender, COUNT(*) as count FROM emails WHERE timestamp > ? GROUP BY sender HAVING count > 100",
                threat_types=[ThreatType.SPAM, ThreatType.PHISHING],
                lookback_hours=24,
                enabled=True,
                last_run=None,
                hit_count=0,
                false_positive_rate=0.1
            ),
            
            HuntingQuery(
                query_id="credential_harvesting_patterns",
                name="Credential Harvesting Patterns",
                description="Detect emails with credential harvesting indicators",
                query_logic="SELECT * FROM emails WHERE (subject LIKE '%verify%account%' OR body LIKE '%login%credentials%') AND sender NOT IN (trusted_senders)",
                threat_types=[ThreatType.CREDENTIAL_HARVESTING, ThreatType.PHISHING],
                lookback_hours=4,
                enabled=True,
                last_run=None,
                hit_count=0,
                false_positive_rate=0.05
            ),
            
            HuntingQuery(
                query_id="bec_executive_impersonation",
                name="BEC Executive Impersonation",
                description="Detect Business Email Compromise attempts targeting executives",
                query_logic="SELECT * FROM emails WHERE display_name IN (executives) AND sender_domain != company_domain",
                threat_types=[ThreatType.BEC, ThreatType.SOCIAL_ENGINEERING],
                lookback_hours=12,
                enabled=True,
                last_run=None,
                hit_count=0,
                false_positive_rate=0.2
            ),
            
            HuntingQuery(
                query_id="malware_attachment_surge",
                name="Malware Attachment Surge",
                description="Detect sudden increase in malicious attachments",
                query_logic="SELECT attachment_hash, COUNT(*) FROM emails WHERE has_attachments=1 AND malware_detected=1 AND timestamp > ? GROUP BY attachment_hash HAVING COUNT(*) > 5",
                threat_types=[ThreatType.MALWARE, ThreatType.RANSOMWARE],
                lookback_hours=2,
                enabled=True,
                last_run=None,
                hit_count=0,
                false_positive_rate=0.01
            ),
            
            HuntingQuery(
                query_id="data_exfiltration_keywords",
                name="Data Exfiltration Keywords",
                description="Detect emails with data exfiltration indicators",
                query_logic="SELECT * FROM emails WHERE (subject LIKE '%confidential%' OR subject LIKE '%sensitive%') AND external_recipient=1",
                threat_types=[ThreatType.DATA_EXFILTRATION, ThreatType.INSIDER_THREAT],
                lookback_hours=8,
                enabled=True,
                last_run=None,
                hit_count=0,
                false_positive_rate=0.3
            )
        ]
        
        for query in queries:
            self.hunting_queries[query.query_id] = query
    
    async def __aenter__(self):
        """Async context manager entry"""
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30)
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()
    
    async def create_incident(self, title: str, description: str,
                            severity: IncidentSeverity, threat_type: ThreatType,
                            affected_emails: List[str], affected_users: List[str] = None,
                            indicators: List[ThreatIndicator] = None) -> SecurityIncident:
        """Create new security incident"""
        try:
            incident_id = str(uuid.uuid4())
            current_time = datetime.now(timezone.utc)
            
            # Calculate impact assessment
            impact_assessment = await self._assess_incident_impact(
                severity, threat_type, affected_emails, affected_users or []
            )
            
            # Calculate false positive likelihood
            false_positive_likelihood = self._calculate_false_positive_likelihood(
                threat_type, indicators or [], impact_assessment
            )
            
            # Create incident
            incident = SecurityIncident(
                incident_id=incident_id,
                title=title,
                description=description,
                severity=severity,
                status=IncidentStatus.NEW,
                threat_type=threat_type,
                affected_users=affected_users or [],
                affected_emails=affected_emails,
                indicators=indicators or [],
                created_timestamp=current_time,
                updated_timestamp=current_time,
                assigned_to=None,
                escalation_level=0,
                remediation_actions=[],
                timeline=[{
                    'timestamp': current_time.isoformat(),
                    'action': 'incident_created',
                    'details': f'Incident created with severity {severity.value}'
                }],
                false_positive_likelihood=false_positive_likelihood,
                impact_assessment=impact_assessment
            )
            
            # Store incident
            self.active_incidents[incident_id] = incident
            await self._store_incident(incident)
            
            # Create initial alerts
            if self.config.get('auto_escalation_enabled', True):
                await self._send_incident_alerts(incident)
            
            # Create automatic remediation tasks if enabled
            if self.config.get('auto_remediation_enabled', True):
                await self._create_auto_remediation_tasks(incident)
            
            # Update statistics
            self.response_stats['total_incidents'] += 1
            if severity.value not in self.response_stats['incidents_by_severity']:
                self.response_stats['incidents_by_severity'][severity.value] = 0
            self.response_stats['incidents_by_severity'][severity.value] += 1
            
            logger.info(f"Created security incident {incident_id}: {title} ({severity.value})")
            return incident
            
        except Exception as e:
            logger.error(f"Error creating incident: {str(e)}")
            raise
    
    async def _assess_incident_impact(self, severity: IncidentSeverity, threat_type: ThreatType,
                                    affected_emails: List[str], affected_users: List[str]) -> Dict[str, Any]:
        """Assess the business impact of the incident"""
        try:
            impact = {
                'user_count': len(affected_users),
                'email_count': len(affected_emails),
                'business_impact_score': 0.0,
                'data_sensitivity': 'unknown',
                'regulatory_implications': [],
                'estimated_cost': 0.0,
                'downtime_minutes': 0
            }
            
            # Calculate business impact score
            base_score = 0.0
            
            # Severity contribution
            severity_weights = {
                IncidentSeverity.CRITICAL: 10.0,
                IncidentSeverity.HIGH: 7.5,
                IncidentSeverity.MEDIUM: 5.0,
                IncidentSeverity.LOW: 2.5,
                IncidentSeverity.INFORMATIONAL: 1.0
            }
            base_score += severity_weights.get(severity, 5.0)
            
            # Threat type contribution
            threat_weights = {
                ThreatType.RANSOMWARE: 10.0,
                ThreatType.DATA_EXFILTRATION: 9.0,
                ThreatType.BEC: 8.0,
                ThreatType.APT: 8.5,
                ThreatType.MALWARE: 7.0,
                ThreatType.PHISHING: 6.0,
                ThreatType.CREDENTIAL_HARVESTING: 6.5,
                ThreatType.INSIDER_THREAT: 7.5,
                ThreatType.SOCIAL_ENGINEERING: 5.0,
                ThreatType.SPAM: 2.0
            }
            base_score += threat_weights.get(threat_type, 5.0)
            
            # Scale impact
            user_multiplier = min(len(affected_users) / 100.0, 2.0)  # Cap at 2x
            email_multiplier = min(len(affected_emails) / 1000.0, 1.5)  # Cap at 1.5x
            
            impact['business_impact_score'] = base_score * (1 + user_multiplier + email_multiplier)
            
            # Estimate cost (simplified model)
            cost_per_user = {
                IncidentSeverity.CRITICAL: 5000,
                IncidentSeverity.HIGH: 2000,
                IncidentSeverity.MEDIUM: 500,
                IncidentSeverity.LOW: 100,
                IncidentSeverity.INFORMATIONAL: 10
            }
            impact['estimated_cost'] = len(affected_users) * cost_per_user.get(severity, 500)
            
            # Check for regulatory implications
            if threat_type in [ThreatType.DATA_EXFILTRATION, ThreatType.INSIDER_THREAT]:
                impact['regulatory_implications'] = ['GDPR', 'SOX', 'HIPAA']
            elif threat_type == ThreatType.RANSOMWARE:
                impact['regulatory_implications'] = ['Cybersecurity Incident Reporting']
            
            return impact
            
        except Exception as e:
            logger.error(f"Error assessing incident impact: {str(e)}")
            return {'business_impact_score': 5.0, 'user_count': len(affected_users)}
    
    def _calculate_false_positive_likelihood(self, threat_type: ThreatType,
                                           indicators: List[ThreatIndicator],
                                           impact_assessment: Dict[str, Any]) -> float:
        """Calculate likelihood that incident is a false positive"""
        try:
            fp_score = 0.0
            
            # Base false positive rates by threat type
            base_rates = {
                ThreatType.SPAM: 0.3,
                ThreatType.PHISHING: 0.1,
                ThreatType.MALWARE: 0.05,
                ThreatType.BEC: 0.15,
                ThreatType.RANSOMWARE: 0.02,
                ThreatType.CREDENTIAL_HARVESTING: 0.08,
                ThreatType.DATA_EXFILTRATION: 0.25,
                ThreatType.SOCIAL_ENGINEERING: 0.2,
                ThreatType.INSIDER_THREAT: 0.4,
                ThreatType.APT: 0.05
            }
            
            fp_score = base_rates.get(threat_type, 0.15)
            
            # Adjust based on indicator confidence
            if indicators:
                avg_confidence = sum(ind.confidence for ind in indicators) / len(indicators)
                # High confidence indicators reduce false positive likelihood
                fp_score *= (1 - avg_confidence * 0.5)
            
            # Adjust based on impact
            business_impact = impact_assessment.get('business_impact_score', 5.0)
            if business_impact > 15.0:  # High impact reduces FP likelihood
                fp_score *= 0.7
            elif business_impact < 5.0:  # Low impact increases FP likelihood
                fp_score *= 1.3
            
            return min(max(fp_score, 0.0), 1.0)
            
        except Exception as e:
            logger.error(f"Error calculating false positive likelihood: {str(e)}")
            return 0.15
    
    async def _send_incident_alerts(self, incident: SecurityIncident):
        """Send incident alerts through configured channels"""
        try:
            channels = self.config.get('notification_channels', {}).get(
                incident.severity.value, ['email']
            )
            
            for channel_name in channels:
                try:
                    channel = AlertChannel(channel_name)
                    await self._send_alert_notification(incident, channel)
                except ValueError:
                    logger.warning(f"Unknown alert channel: {channel_name}")
                    
        except Exception as e:
            logger.error(f"Error sending incident alerts: {str(e)}")
    
    async def _send_alert_notification(self, incident: SecurityIncident, channel: AlertChannel):
        """Send alert notification through specific channel"""
        try:
            alert_id = str(uuid.uuid4())
            
            # Format alert message
            subject = f"[SECURITY ALERT] {incident.severity.value.upper()}: {incident.title}"
            
            message = f"""
Security Incident Alert

Incident ID: {incident.incident_id}
Severity: {incident.severity.value.upper()}
Threat Type: {incident.threat_type.value}
Status: {incident.status.value}

Description: {incident.description}

Affected Users: {len(incident.affected_users)}
Affected Emails: {len(incident.affected_emails)}

Business Impact Score: {incident.impact_assessment.get('business_impact_score', 'Unknown')}
False Positive Likelihood: {incident.false_positive_likelihood:.1%}

Created: {incident.created_timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}

Please investigate and respond according to incident response procedures.
            """.strip()
            
            # Get recipients based on channel and severity
            recipients = await self._get_alert_recipients(channel, incident.severity)
            
            # Create alert notification
            alert = AlertNotification(
                alert_id=alert_id,
                incident_id=incident.incident_id,
                channel=channel,
                recipients=recipients,
                subject=subject,
                message=message,
                urgency=incident.severity.value,
                sent_timestamp=None,
                delivery_status='pending',
                retry_count=0
            )
            
            # Send notification based on channel
            success = False
            if channel == AlertChannel.EMAIL:
                success = await self._send_email_alert(alert)
            elif channel == AlertChannel.SIEM:
                success = await self._send_siem_alert(alert, incident)
            elif channel == AlertChannel.TEAMS:
                success = await self._send_teams_alert(alert)
            elif channel == AlertChannel.SLACK:
                success = await self._send_slack_alert(alert)
            elif channel == AlertChannel.WEBHOOK:
                success = await self._send_webhook_alert(alert, incident)
            
            # Update alert status
            alert.delivery_status = 'sent' if success else 'failed'
            alert.sent_timestamp = datetime.now(timezone.utc) if success else None
            
            # Store alert
            await self._store_alert_notification(alert)
            
            if success:
                logger.info(f"Sent {channel.value} alert for incident {incident.incident_id}")
            else:
                logger.error(f"Failed to send {channel.value} alert for incident {incident.incident_id}")
                
        except Exception as e:
            logger.error(f"Error sending alert notification: {str(e)}")
    
    async def _get_alert_recipients(self, channel: AlertChannel, severity: IncidentSeverity) -> List[str]:
        """Get alert recipients based on channel and severity"""
        try:
            # This would typically integrate with directory services or configuration
            recipients = []
            
            if channel == AlertChannel.EMAIL:
                if severity in [IncidentSeverity.CRITICAL, IncidentSeverity.HIGH]:
                    recipients = ['security-team@isectech.com', 'soc@isectech.com']
                else:
                    recipients = ['security-alerts@isectech.com']
            
            elif channel == AlertChannel.SIEM:
                recipients = ['siem-integration']
            
            elif channel == AlertChannel.TEAMS:
                recipients = ['security-team-channel']
            
            elif channel == AlertChannel.SLACK:
                recipients = ['#security-alerts']
            
            return recipients
            
        except Exception as e:
            logger.error(f"Error getting alert recipients: {str(e)}")
            return []
    
    async def _send_email_alert(self, alert: AlertNotification) -> bool:
        """Send email alert notification"""
        try:
            # This would integrate with email service (SMTP, API)
            logger.info(f"Email alert sent to {alert.recipients}: {alert.subject}")
            return True
            
        except Exception as e:
            logger.error(f"Error sending email alert: {str(e)}")
            return False
    
    async def _send_siem_alert(self, alert: AlertNotification, incident: SecurityIncident) -> bool:
        """Send alert to SIEM system"""
        try:
            if not self.config.get('siem_integration_enabled', False):
                return False
            
            # Format SIEM event
            siem_event = {
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'event_type': 'security_incident',
                'severity': incident.severity.value,
                'incident_id': incident.incident_id,
                'threat_type': incident.threat_type.value,
                'affected_users': incident.affected_users,
                'affected_emails': incident.affected_emails,
                'indicators': [asdict(ind) for ind in incident.indicators],
                'business_impact_score': incident.impact_assessment.get('business_impact_score'),
                'source': 'isectech_email_security'
            }
            
            # Send to SIEM (would use actual SIEM API)
            logger.info(f"SIEM alert sent for incident {incident.incident_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error sending SIEM alert: {str(e)}")
            return False
    
    async def _send_teams_alert(self, alert: AlertNotification) -> bool:
        """Send Microsoft Teams alert"""
        try:
            # This would integrate with Teams webhook
            logger.info(f"Teams alert sent: {alert.subject}")
            return True
            
        except Exception as e:
            logger.error(f"Error sending Teams alert: {str(e)}")
            return False
    
    async def _send_slack_alert(self, alert: AlertNotification) -> bool:
        """Send Slack alert"""
        try:
            # This would integrate with Slack API
            logger.info(f"Slack alert sent: {alert.subject}")
            return True
            
        except Exception as e:
            logger.error(f"Error sending Slack alert: {str(e)}")
            return False
    
    async def _send_webhook_alert(self, alert: AlertNotification, incident: SecurityIncident) -> bool:
        """Send webhook alert"""
        try:
            webhook_url = self.config.get('webhook_url')
            if not webhook_url:
                return False
            
            payload = {
                'alert_id': alert.alert_id,
                'incident': asdict(incident),
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
            
            async with self.session.post(webhook_url, json=payload) as response:
                return response.status == 200
                
        except Exception as e:
            logger.error(f"Error sending webhook alert: {str(e)}")
            return False
    
    async def _create_auto_remediation_tasks(self, incident: SecurityIncident):
        """Create automatic remediation tasks based on incident"""
        try:
            tasks = []
            
            # Determine remediation actions based on threat type and severity
            if incident.threat_type == ThreatType.PHISHING:
                tasks.extend([
                    RemediationAction.QUARANTINE_EMAIL,
                    RemediationAction.BLOCK_SENDER,
                    RemediationAction.NOTIFY_USERS
                ])
                
                if incident.severity in [IncidentSeverity.CRITICAL, IncidentSeverity.HIGH]:
                    tasks.append(RemediationAction.RECALL_EMAIL)
            
            elif incident.threat_type == ThreatType.MALWARE:
                tasks.extend([
                    RemediationAction.QUARANTINE_EMAIL,
                    RemediationAction.RECALL_EMAIL,
                    RemediationAction.BLOCK_SENDER,
                    RemediationAction.DISABLE_LINKS
                ])
            
            elif incident.threat_type == ThreatType.BEC:
                tasks.extend([
                    RemediationAction.QUARANTINE_EMAIL,
                    RemediationAction.NOTIFY_USERS,
                    RemediationAction.RESET_PASSWORDS
                ])
                
                if incident.severity == IncidentSeverity.CRITICAL:
                    tasks.append(RemediationAction.BLOCK_DOMAIN)
            
            elif incident.threat_type == ThreatType.SPAM:
                tasks.extend([
                    RemediationAction.MOVE_TO_JUNK,
                    RemediationAction.BLOCK_SENDER
                ])
            
            # Create remediation tasks
            for i, action in enumerate(tasks):
                task = RemediationTask(
                    task_id=str(uuid.uuid4()),
                    incident_id=incident.incident_id,
                    action=action,
                    target_emails=incident.affected_emails,
                    target_users=incident.affected_users,
                    parameters={},
                    priority=len(tasks) - i,  # Higher priority for earlier tasks
                    estimated_duration=self._estimate_remediation_duration(action),
                    dependencies=[],
                    status='pending',
                    created_timestamp=datetime.now(timezone.utc),
                    scheduled_timestamp=None,
                    completed_timestamp=None,
                    success=None,
                    error_message=None
                )
                
                # Check if approval is required
                approval_required = self.config.get('remediation_approval_required', {}).get(
                    incident.severity.value, True
                )
                
                if not approval_required:
                    self.remediation_queue.append(task)
                    await self._store_remediation_task(task)
                else:
                    task.status = 'awaiting_approval'
                    await self._store_remediation_task(task)
                
                logger.info(f"Created remediation task {task.task_id}: {action.value}")
            
        except Exception as e:
            logger.error(f"Error creating auto-remediation tasks: {str(e)}")
    
    def _estimate_remediation_duration(self, action: RemediationAction) -> int:
        """Estimate remediation task duration in minutes"""
        durations = {
            RemediationAction.QUARANTINE_EMAIL: 2,
            RemediationAction.RECALL_EMAIL: 5,
            RemediationAction.DELETE_EMAIL: 1,
            RemediationAction.MOVE_TO_JUNK: 1,
            RemediationAction.DISABLE_LINKS: 3,
            RemediationAction.BLOCK_SENDER: 2,
            RemediationAction.ADD_SAFE_SENDER: 1,
            RemediationAction.NOTIFY_USERS: 10,
            RemediationAction.RESET_PASSWORDS: 30,
            RemediationAction.BLOCK_DOMAIN: 5,
            RemediationAction.CREATE_TRANSPORT_RULE: 10
        }
        
        return durations.get(action, 5)
    
    async def execute_remediation_task(self, task_id: str) -> bool:
        """Execute a specific remediation task"""
        try:
            # Find task
            task = None
            for t in self.remediation_queue:
                if t.task_id == task_id:
                    task = t
                    break
            
            if not task:
                logger.error(f"Remediation task not found: {task_id}")
                return False
            
            # Update task status
            task.status = 'executing'
            task.scheduled_timestamp = datetime.now(timezone.utc)
            
            logger.info(f"Executing remediation task {task_id}: {task.action.value}")
            
            # Execute based on action type
            success = False
            error_message = None
            
            try:
                if task.action == RemediationAction.QUARANTINE_EMAIL:
                    success = await self._quarantine_emails(task.target_emails)
                elif task.action == RemediationAction.RECALL_EMAIL:
                    success = await self._recall_emails(task.target_emails)
                elif task.action == RemediationAction.DELETE_EMAIL:
                    success = await self._delete_emails(task.target_emails)
                elif task.action == RemediationAction.MOVE_TO_JUNK:
                    success = await self._move_emails_to_junk(task.target_emails)
                elif task.action == RemediationAction.BLOCK_SENDER:
                    success = await self._block_senders(task.target_emails)
                elif task.action == RemediationAction.NOTIFY_USERS:
                    success = await self._notify_users(task.target_users, task.incident_id)
                elif task.action == RemediationAction.RESET_PASSWORDS:
                    success = await self._reset_user_passwords(task.target_users)
                elif task.action == RemediationAction.DISABLE_LINKS:
                    success = await self._disable_email_links(task.target_emails)
                else:
                    error_message = f"Unsupported remediation action: {task.action.value}"
                    success = False
            
            except Exception as e:
                error_message = str(e)
                success = False
            
            # Update task completion
            task.status = 'completed' if success else 'failed'
            task.completed_timestamp = datetime.now(timezone.utc)
            task.success = success
            task.error_message = error_message
            
            # Update database
            await self._store_remediation_task(task)
            
            # Remove from queue if completed
            if task.status in ['completed', 'failed']:
                self.remediation_queue = [t for t in self.remediation_queue if t.task_id != task_id]
                
                # Update incident timeline
                incident = self.active_incidents.get(task.incident_id)
                if incident:
                    incident.timeline.append({
                        'timestamp': datetime.now(timezone.utc).isoformat(),
                        'action': f'remediation_{task.status}',
                        'details': f'{task.action.value}: {success}'
                    })
                    incident.remediation_actions.append(task.action.value)
                    await self._store_incident(incident)
            
            logger.info(f"Remediation task {task_id} completed: {success}")
            return success
            
        except Exception as e:
            logger.error(f"Error executing remediation task {task_id}: {str(e)}")
            return False
    
    async def _quarantine_emails(self, email_ids: List[str]) -> bool:
        """Quarantine specified emails"""
        try:
            # This would integrate with email provider APIs
            logger.info(f"Quarantining {len(email_ids)} emails")
            return True
            
        except Exception as e:
            logger.error(f"Error quarantining emails: {str(e)}")
            return False
    
    async def _recall_emails(self, email_ids: List[str]) -> bool:
        """Recall/delete specified emails from user mailboxes"""
        try:
            # This would integrate with email provider APIs for post-delivery recall
            logger.info(f"Recalling {len(email_ids)} emails")
            return True
            
        except Exception as e:
            logger.error(f"Error recalling emails: {str(e)}")
            return False
    
    async def _delete_emails(self, email_ids: List[str]) -> bool:
        """Delete specified emails"""
        try:
            logger.info(f"Deleting {len(email_ids)} emails")
            return True
            
        except Exception as e:
            logger.error(f"Error deleting emails: {str(e)}")
            return False
    
    async def _move_emails_to_junk(self, email_ids: List[str]) -> bool:
        """Move emails to junk folder"""
        try:
            logger.info(f"Moving {len(email_ids)} emails to junk")
            return True
            
        except Exception as e:
            logger.error(f"Error moving emails to junk: {str(e)}")
            return False
    
    async def _block_senders(self, email_ids: List[str]) -> bool:
        """Block senders of specified emails"""
        try:
            logger.info(f"Blocking senders for {len(email_ids)} emails")
            return True
            
        except Exception as e:
            logger.error(f"Error blocking senders: {str(e)}")
            return False
    
    async def _notify_users(self, user_ids: List[str], incident_id: str) -> bool:
        """Notify users about security incident"""
        try:
            logger.info(f"Notifying {len(user_ids)} users about incident {incident_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error notifying users: {str(e)}")
            return False
    
    async def _reset_user_passwords(self, user_ids: List[str]) -> bool:
        """Reset passwords for specified users"""
        try:
            logger.info(f"Resetting passwords for {len(user_ids)} users")
            return True
            
        except Exception as e:
            logger.error(f"Error resetting passwords: {str(e)}")
            return False
    
    async def _disable_email_links(self, email_ids: List[str]) -> bool:
        """Disable links in specified emails"""
        try:
            logger.info(f"Disabling links in {len(email_ids)} emails")
            return True
            
        except Exception as e:
            logger.error(f"Error disabling links: {str(e)}")
            return False
    
    async def run_threat_hunting(self, query_id: Optional[str] = None) -> Dict[str, Any]:
        """Run threat hunting queries"""
        try:
            results = {}
            queries_to_run = []
            
            if query_id:
                if query_id in self.hunting_queries:
                    queries_to_run = [self.hunting_queries[query_id]]
            else:
                queries_to_run = [q for q in self.hunting_queries.values() if q.enabled]
            
            for query in queries_to_run:
                start_time = datetime.now(timezone.utc)
                
                try:
                    # Execute hunting query (simplified - would query email database)
                    hits = await self._execute_hunting_query(query)
                    
                    processing_time = (datetime.now(timezone.utc) - start_time).total_seconds()
                    
                    # Update query statistics
                    query.last_run = start_time
                    query.hit_count += len(hits)
                    
                    # Store results
                    result_id = str(uuid.uuid4())
                    await self._store_hunting_result(result_id, query.query_id, hits, start_time, processing_time)
                    
                    results[query.query_id] = {
                        'query_name': query.name,
                        'hits': len(hits),
                        'processing_time': processing_time,
                        'results': hits[:10]  # Limit results for response
                    }
                    
                    # Create incidents for high-confidence hits
                    if hits and len(hits) > query.false_positive_rate * 100:
                        await self._create_hunting_incidents(query, hits)
                    
                    logger.info(f"Hunting query {query.query_id} found {len(hits)} hits")
                    
                except Exception as e:
                    logger.error(f"Error executing hunting query {query.query_id}: {str(e)}")
                    results[query.query_id] = {'error': str(e)}
            
            return results
            
        except Exception as e:
            logger.error(f"Error running threat hunting: {str(e)}")
            return {'error': str(e)}
    
    async def _execute_hunting_query(self, query: HuntingQuery) -> List[Dict[str, Any]]:
        """Execute a threat hunting query"""
        try:
            # This would execute against the email database
            # For demonstration, return mock results
            hits = []
            
            if query.query_id == "suspicious_sender_volume":
                hits = [
                    {'sender': 'suspicious@example.com', 'count': 150, 'risk_score': 8.5},
                    {'sender': 'spam@badsite.tk', 'count': 200, 'risk_score': 9.2}
                ]
            elif query.query_id == "credential_harvesting_patterns":
                hits = [
                    {'email_id': 'email123', 'sender': 'fake-bank@phishing.com', 'risk_score': 9.0}
                ]
            
            return hits
            
        except Exception as e:
            logger.error(f"Error executing hunting query: {str(e)}")
            return []
    
    async def _create_hunting_incidents(self, query: HuntingQuery, hits: List[Dict[str, Any]]):
        """Create incidents from hunting query results"""
        try:
            for hit in hits:
                if hit.get('risk_score', 0) > 7.0:  # High confidence threshold
                    # Create incident
                    await self.create_incident(
                        title=f"Threat Hunt Detection: {query.name}",
                        description=f"Hunting query '{query.name}' detected suspicious activity",
                        severity=IncidentSeverity.MEDIUM,
                        threat_type=query.threat_types[0] if query.threat_types else ThreatType.SUSPICIOUS,
                        affected_emails=[hit.get('email_id', '')],
                        affected_users=[],
                        indicators=[
                            ThreatIndicator(
                                indicator_type="hunting_result",
                                value=str(hit),
                                confidence=hit.get('risk_score', 5.0) / 10.0,
                                severity=IncidentSeverity.MEDIUM,
                                description=f"Detected by hunting query: {query.name}",
                                source="threat_hunting",
                                created_timestamp=datetime.now(timezone.utc)
                            )
                        ]
                    )
            
        except Exception as e:
            logger.error(f"Error creating hunting incidents: {str(e)}")
    
    async def _store_incident(self, incident: SecurityIncident):
        """Store incident in database"""
        try:
            self.db_connection.execute('''
                INSERT OR REPLACE INTO incidents
                (incident_id, title, description, severity, status, threat_type,
                 affected_users, affected_emails, created_timestamp, updated_timestamp,
                 assigned_to, escalation_level, false_positive_likelihood, impact_assessment)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                incident.incident_id,
                incident.title,
                incident.description,
                incident.severity.value,
                incident.status.value,
                incident.threat_type.value,
                json.dumps(incident.affected_users),
                json.dumps(incident.affected_emails),
                incident.created_timestamp.timestamp(),
                incident.updated_timestamp.timestamp(),
                incident.assigned_to,
                incident.escalation_level,
                incident.false_positive_likelihood,
                json.dumps(incident.impact_assessment)
            ))
            
            self.db_connection.commit()
            
        except Exception as e:
            logger.error(f"Error storing incident: {str(e)}")
    
    async def _store_remediation_task(self, task: RemediationTask):
        """Store remediation task in database"""
        try:
            self.db_connection.execute('''
                INSERT OR REPLACE INTO remediation_tasks
                (task_id, incident_id, action, target_emails, target_users,
                 parameters, priority, status, created_timestamp, scheduled_timestamp,
                 completed_timestamp, success, error_message)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                task.task_id,
                task.incident_id,
                task.action.value,
                json.dumps(task.target_emails),
                json.dumps(task.target_users),
                json.dumps(task.parameters),
                task.priority,
                task.status,
                task.created_timestamp.timestamp(),
                task.scheduled_timestamp.timestamp() if task.scheduled_timestamp else None,
                task.completed_timestamp.timestamp() if task.completed_timestamp else None,
                task.success,
                task.error_message
            ))
            
            self.db_connection.commit()
            
        except Exception as e:
            logger.error(f"Error storing remediation task: {str(e)}")
    
    async def _store_alert_notification(self, alert: AlertNotification):
        """Store alert notification in database"""
        try:
            self.db_connection.execute('''
                INSERT OR REPLACE INTO alert_notifications
                (alert_id, incident_id, channel, recipients, subject, message,
                 urgency, sent_timestamp, delivery_status, retry_count)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                alert.alert_id,
                alert.incident_id,
                alert.channel.value,
                json.dumps(alert.recipients),
                alert.subject,
                alert.message,
                alert.urgency,
                alert.sent_timestamp.timestamp() if alert.sent_timestamp else None,
                alert.delivery_status,
                alert.retry_count
            ))
            
            self.db_connection.commit()
            
        except Exception as e:
            logger.error(f"Error storing alert notification: {str(e)}")
    
    async def _store_hunting_result(self, result_id: str, query_id: str, hits: List[Dict[str, Any]],
                                   execution_time: datetime, processing_time: float):
        """Store hunting query result"""
        try:
            self.db_connection.execute('''
                INSERT INTO hunting_results
                (result_id, query_id, execution_timestamp, hit_count, results, processing_time)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                result_id,
                query_id,
                execution_time.timestamp(),
                len(hits),
                json.dumps(hits),
                processing_time
            ))
            
            self.db_connection.commit()
            
        except Exception as e:
            logger.error(f"Error storing hunting result: {str(e)}")
    
    def get_incident_statistics(self) -> Dict[str, Any]:
        """Get incident response statistics"""
        try:
            return {
                'total_incidents': self.response_stats['total_incidents'],
                'incidents_by_severity': self.response_stats['incidents_by_severity'],
                'active_incidents': len(self.active_incidents),
                'pending_remediation_tasks': len(self.remediation_queue),
                'mean_response_time': self.response_stats.get('mean_response_time', 0.0),
                'remediation_success_rate': self.response_stats.get('remediation_success_rate', 0.0),
                'false_positive_rate': self.response_stats.get('false_positive_rate', 0.0)
            }
            
        except Exception as e:
            logger.error(f"Error getting incident statistics: {str(e)}")
            return {}
    
    def __del__(self):
        """Cleanup resources"""
        try:
            if hasattr(self, 'db_connection'):
                self.db_connection.close()
        except Exception:
            pass


# Example usage and testing
async def main():
    """Example usage of SecurityResponseEngine"""
    
    try:
        async with SecurityResponseEngine() as response_engine:
            # Create test incident
            incident = await response_engine.create_incident(
                title="Phishing Campaign Detected",
                description="Multiple users received phishing emails impersonating bank login pages",
                severity=IncidentSeverity.HIGH,
                threat_type=ThreatType.PHISHING,
                affected_emails=['email1@example.com', 'email2@example.com'],
                affected_users=['user1@isectech.com', 'user2@isectech.com'],
                indicators=[
                    ThreatIndicator(
                        indicator_type="domain",
                        value="fake-bank.tk",
                        confidence=0.9,
                        severity=IncidentSeverity.HIGH,
                        description="Suspicious domain impersonating legitimate bank",
                        source="url_analyzer",
                        created_timestamp=datetime.now(timezone.utc)
                    )
                ]
            )
            
            print(f"Created incident: {incident.incident_id}")
            print(f"Severity: {incident.severity.value}")
            print(f"Business Impact Score: {incident.impact_assessment['business_impact_score']}")
            print(f"False Positive Likelihood: {incident.false_positive_likelihood:.1%}")
            
            # Run threat hunting
            print("\nRunning threat hunting...")
            hunting_results = await response_engine.run_threat_hunting()
            
            for query_id, result in hunting_results.items():
                if 'error' not in result:
                    print(f"Query {query_id}: {result['hits']} hits in {result['processing_time']:.2f}s")
            
            # Get statistics
            stats = response_engine.get_incident_statistics()
            print(f"\nIncident Statistics:")
            for key, value in stats.items():
                print(f"  {key}: {value}")
        
    except Exception as e:
        logger.error(f"Error in example: {str(e)}")


if __name__ == "__main__":
    asyncio.run(main())