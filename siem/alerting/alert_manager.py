#!/usr/bin/env python3
"""
iSECTECH SIEM Real-Time Alert Manager
Production-grade alerting system with multi-channel notifications
Intelligent alert routing, deduplication, and escalation management

🚨 EMERGENCY SECURITY: Enhanced with critical security hardening to prevent
SIEM/SOAR manipulation attacks (CVSS 9.4) that could disable monitoring
"""

import asyncio
import json
import logging
import sys
import os

# CRITICAL: Add emergency security hardening
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'security'))
try:
    from emergency_siem_hardening import emergency_siem_hardening
    EMERGENCY_HARDENING_ACTIVE = True
    logging.info("🔒 EMERGENCY SECURITY: SIEM/SOAR hardening ACTIVATED")
except ImportError as e:
    EMERGENCY_HARDENING_ACTIVE = False
    logging.error(f"🚨 CRITICAL: Emergency hardening failed to load: {e}")
import smtplib
import ssl
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, asdict
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
import requests
import yaml
import redis.asyncio as redis
import psycopg2
from psycopg2.extras import RealDictCursor
from aiokafka import AIOKafkaConsumer, AIOKafkaProducer
from jinja2 import Template, Environment, FileSystemLoader
import aiohttp
from collections import defaultdict, deque
import hashlib
import time
import uuid

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class Alert:
    """Alert data structure"""
    alert_id: str
    title: str
    description: str
    severity: str  # critical, high, medium, low
    category: str  # security_incident, anomaly, compliance, system
    source: str    # detection engine, correlation, ml, manual
    event_ids: List[str]
    affected_assets: List[str]
    indicators: Dict[str, Any]
    metadata: Dict[str, Any]
    created_at: datetime
    updated_at: datetime
    status: str    # new, acknowledged, investigating, resolved, closed
    assigned_to: Optional[str] = None
    escalation_level: int = 0
    suppressed: bool = False
    parent_alert_id: Optional[str] = None
    child_alert_ids: List[str] = None

@dataclass
class NotificationChannel:
    """Notification channel configuration"""
    name: str
    type: str  # email, slack, teams, webhook, sms, pagerduty
    config: Dict[str, Any]
    enabled: bool
    severity_filter: List[str]
    category_filter: List[str]
    rate_limit: int  # Max notifications per hour
    escalation_delay: int  # Minutes before escalation

@dataclass
class AlertRule:
    """Alert rule configuration"""
    rule_id: str
    name: str
    description: str
    conditions: Dict[str, Any]
    severity: str
    category: str
    notification_channels: List[str]
    suppression_window: int  # Minutes
    auto_resolve: bool
    escalation_rules: List[Dict[str, Any]]
    enabled: bool

class AlertManager:
    """
    Production alert manager for SIEM system
    Handles real-time alerting, notification routing, and escalation
    """
    
    def __init__(self, config_path: str):
        self.config_path = Path(config_path)
        self.config = {}
        self.redis_client = None
        self.db_connection = None
        self.kafka_consumer = None
        self.kafka_producer = None
        self.notification_channels = {}
        self.alert_rules = {}
        self.template_env = None
        
        # Alert tracking
        self.active_alerts = {}
        self.alert_cache = deque(maxlen=10000)
        self.suppressed_alerts = set()
        self.rate_limiters = defaultdict(lambda: {'count': 0, 'reset_time': time.time() + 3600})
        
        # Escalation tracking
        self.escalation_timers = {}
        self.pending_escalations = defaultdict(list)
        
        # Performance metrics
        self.metrics = {
            'alerts_generated': 0,
            'alerts_suppressed': 0,
            'notifications_sent': 0,
            'escalations_triggered': 0,
            'avg_response_time': 0.0
        }
        
    async def initialize(self):
        """Initialize the alert manager"""
        try:
            await self._load_config()
            await self._setup_database()
            await self._setup_redis()
            await self._setup_kafka()
            await self._load_alert_rules()
            await self._load_notification_channels()
            await self._setup_templates()
            await self._start_background_tasks()
            logger.info("Alert Manager initialized successfully")
        except Exception as e:
            logger.error(f"Alert Manager initialization failed: {e}")
            raise
            
    async def _load_config(self):
        """Load alerting configuration"""
        try:
            with open(self.config_path, 'r') as f:
                self.config = yaml.safe_load(f)
        except Exception as e:
            logger.error(f"Failed to load config: {e}")
            # Use default configuration
            self.config = {
                'database': {'host': 'localhost', 'port': 5432, 'database': 'siem_alerts'},
                'redis': {'host': 'localhost', 'port': 6379, 'db': 4},
                'kafka': {'bootstrap_servers': 'localhost:9092'},
                'smtp': {'host': 'localhost', 'port': 587},
                'templates_path': '/opt/siem/templates'
            }
            
    async def _setup_database(self):
        """Setup PostgreSQL connection"""
        try:
            db_config = self.config.get('database', {})
            self.db_connection = psycopg2.connect(
                host=db_config.get('host', 'localhost'),
                port=db_config.get('port', 5432),
                database=db_config.get('database', 'siem_alerts'),
                user=db_config.get('user', 'alert_user'),
                password=db_config.get('password', 'alert_password'),
                cursor_factory=RealDictCursor
            )
            self.db_connection.autocommit = True
            logger.info("Database connection established")
        except Exception as e:
            logger.warning(f"Database connection failed: {e}")
            self.db_connection = None
            
    async def _setup_redis(self):
        """Setup Redis connection"""
        try:
            redis_config = self.config.get('redis', {})
            self.redis_client = redis.Redis(
                host=redis_config.get('host', 'localhost'),
                port=redis_config.get('port', 6379),
                db=redis_config.get('db', 4),
                decode_responses=True
            )
            await self.redis_client.ping()
            logger.info("Redis connection established")
        except Exception as e:
            logger.warning(f"Redis connection failed: {e}")
            self.redis_client = None
            
    async def _setup_kafka(self):
        """Setup Kafka connections"""
        try:
            kafka_config = self.config.get('kafka', {})
            bootstrap_servers = kafka_config.get('bootstrap_servers', 'localhost:9092')
            
            # Consumer for correlation results and ML alerts
            self.kafka_consumer = AIOKafkaConsumer(
                'correlation-alerts',
                'ml-detected-anomalies',
                'enriched-high-risk-events',
                bootstrap_servers=bootstrap_servers,
                group_id='alert-manager',
                auto_offset_reset='latest',
                value_deserializer=lambda x: json.loads(x.decode('utf-8'))
            )
            
            # Producer for alert notifications
            self.kafka_producer = AIOKafkaProducer(
                bootstrap_servers=bootstrap_servers,
                value_serializer=lambda x: json.dumps(x).encode('utf-8')
            )
            
            await self.kafka_consumer.start()
            await self.kafka_producer.start()
            
            logger.info("Kafka connections established")
            
        except Exception as e:
            logger.warning(f"Kafka setup failed: {e}")
            self.kafka_consumer = None
            self.kafka_producer = None
            
    async def _load_alert_rules(self):
        """Load alert rules from database"""
        try:
            if self.db_connection:
                cursor = self.db_connection.cursor()
                cursor.execute("""
                    SELECT rule_id, name, description, conditions, severity, category,
                           notification_channels, suppression_window, auto_resolve, 
                           escalation_rules, enabled
                    FROM alert_rules 
                    WHERE enabled = true
                """)
                
                for row in cursor.fetchall():
                    rule = AlertRule(
                        rule_id=row['rule_id'],
                        name=row['name'],
                        description=row['description'],
                        conditions=json.loads(row['conditions']),
                        severity=row['severity'],
                        category=row['category'],
                        notification_channels=json.loads(row['notification_channels']),
                        suppression_window=row['suppression_window'],
                        auto_resolve=row['auto_resolve'],
                        escalation_rules=json.loads(row['escalation_rules']),
                        enabled=row['enabled']
                    )
                    self.alert_rules[rule['rule_id']] = rule
                    
                cursor.close()
                logger.info(f"Loaded {len(self.alert_rules)} alert rules")
                
        except Exception as e:
            logger.error(f"Failed to load alert rules: {e}")
            
    async def _load_notification_channels(self):
        """Load notification channels from database"""
        try:
            if self.db_connection:
                cursor = self.db_connection.cursor()
                cursor.execute("""
                    SELECT name, type, config, enabled, severity_filter, 
                           category_filter, rate_limit, escalation_delay
                    FROM notification_channels 
                    WHERE enabled = true
                """)
                
                for row in cursor.fetchall():
                    channel = NotificationChannel(
                        name=row['name'],
                        type=row['type'],
                        config=json.loads(row['config']),
                        enabled=row['enabled'],
                        severity_filter=json.loads(row['severity_filter']),
                        category_filter=json.loads(row['category_filter']),
                        rate_limit=row['rate_limit'],
                        escalation_delay=row['escalation_delay']
                    )
                    self.notification_channels[row['name']] = channel
                    
                cursor.close()
                logger.info(f"Loaded {len(self.notification_channels)} notification channels")
                
        except Exception as e:
            logger.error(f"Failed to load notification channels: {e}")
            
    async def _setup_templates(self):
        """Setup Jinja2 templates for notifications"""
        try:
            templates_path = self.config.get('templates_path', '/opt/siem/templates')
            if Path(templates_path).exists():
                self.template_env = Environment(loader=FileSystemLoader(templates_path))
            else:
                # Create basic templates in memory
                self.template_env = Environment(loader=None)
                await self._create_default_templates()
            logger.info("Templates initialized")
        except Exception as e:
            logger.warning(f"Template setup failed: {e}")
            
    async def _create_default_templates(self):
        """Create default notification templates"""
        # Email template
        email_template = """
Subject: [SIEM Alert] {{ alert.severity.upper() }} - {{ alert.title }}

Alert Details:
- ID: {{ alert.alert_id }}
- Severity: {{ alert.severity.upper() }}
- Category: {{ alert.category }}
- Source: {{ alert.source }}
- Created: {{ alert.created_at }}

Description:
{{ alert.description }}

Affected Assets:
{% for asset in alert.affected_assets %}
- {{ asset }}
{% endfor %}

Indicators:
{% for key, value in alert.indicators.items() %}
- {{ key }}: {{ value }}
{% endfor %}

Event IDs: {{ alert.event_ids|join(', ') }}

Please investigate this alert promptly.

Best regards,
iSECTECH SIEM System
        """
        
        # Slack template
        slack_template = """
{
    "blocks": [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": "🚨 {{ alert.severity.upper() }} Security Alert"
            }
        },
        {
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": "*Alert ID:*\n{{ alert.alert_id }}"
                },
                {
                    "type": "mrkdwn",
                    "text": "*Severity:*\n{{ alert.severity.upper() }}"
                },
                {
                    "type": "mrkdwn",
                    "text": "*Category:*\n{{ alert.category }}"
                },
                {
                    "type": "mrkdwn",
                    "text": "*Source:*\n{{ alert.source }}"
                }
            ]
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "*Description:*\n{{ alert.description }}"
            }
        },
        {
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {
                        "type": "plain_text",
                        "text": "Acknowledge"
                    },
                    "value": "ack_{{ alert.alert_id }}",
                    "action_id": "acknowledge_alert"
                },
                {
                    "type": "button",
                    "text": {
                        "type": "plain_text",
                        "text": "Investigate"
                    },
                    "value": "investigate_{{ alert.alert_id }}",
                    "action_id": "investigate_alert"
                }
            ]
        }
    ]
}
        """
        
        # Store templates (in production, these would be in files)
        self._default_templates = {
            'email': Template(email_template),
            'slack': Template(slack_template)
        }
        
    async def _start_background_tasks(self):
        """Start background processing tasks"""
        # Start Kafka message processing
        if self.kafka_consumer:
            asyncio.create_task(self._process_kafka_messages())
            
        # Start escalation processing
        asyncio.create_task(self._process_escalations())
        
        # Start housekeeping tasks
        asyncio.create_task(self._housekeeping_task())
        
        logger.info("Background tasks started")
        
    async def process_alert(self, alert_data: Dict[str, Any]) -> Alert:
        """
        Process incoming alert data and create alert
        🚨 EMERGENCY SECURITY: Enhanced with critical security validation
        """
        try:
            # 🔒 EMERGENCY SECURITY: Validate alert data for manipulation attempts
            if EMERGENCY_HARDENING_ACTIVE:
                logger.info("🔒 EMERGENCY SECURITY: Validating alert for dangerous parameters")
                
                # Import emergency validation function
                from emergency_event_integrity import validate_siem_event
                
                # Validate alert data for security violations
                secure_event = validate_siem_event(alert_data)
                if secure_event is None:
                    logger.error("🚨 CRITICAL: Alert processing BLOCKED - contains dangerous manipulation parameters")
                    self.metrics['alerts_suppressed'] += 1
                    
                    # Log security incident
                    logger.error(f"🚨 SECURITY INCIDENT: Alert manipulation attempt blocked")
                    logger.error(f"Alert data (sanitized): {self._sanitize_alert_for_logging(alert_data)}")
                    
                    # Create a security violation alert instead
                    security_alert_data = {
                        'title': 'SIEM Alert Manipulation Attempt Detected',
                        'description': 'Critical security violation: Alert contained dangerous parameters that could disable monitoring',
                        'severity': 'critical',
                        'category': 'security_incident',
                        'source': 'emergency_security_hardening',
                        'event_id': f"security-violation-{int(datetime.now(timezone.utc).timestamp())}",
                        'affected_assets': [alert_data.get('source', {}).get('ip', 'unknown')],
                        'indicators': {
                            'manipulation_attempt': True,
                            'original_alert_blocked': True,
                            'security_hardening_active': True
                        },
                        'metadata': {
                            'original_alert_id': alert_data.get('event_id', 'unknown'),
                            'violation_type': 'SIEM_MANIPULATION_ATTEMPT',
                            'emergency_hardening': True
                        }
                    }
                    
                    # Process the security violation alert instead
                    return await self._create_alert_from_data(security_alert_data)
                
                # Use secured alert data for processing
                alert_data = {
                    'event_id': secure_event.event_id,
                    'tenant_id': secure_event.tenant_id,
                    'event_type': secure_event.event_type,
                    'timestamp': secure_event.timestamp.isoformat(),
                    **secure_event.data,
                    '_security_validation': 'EMERGENCY_HARDENING_PASSED',
                    '_security_context': secure_event.security_context
                }
                
                logger.info(f"✅ EMERGENCY SECURITY: Alert validated and secured - {secure_event.event_id}")
            
            # Create alert object from secured data
            alert = await self._create_alert_from_data(alert_data)
            
            # Check for suppression
            if await self._is_alert_suppressed(alert):
                self.metrics['alerts_suppressed'] += 1
                logger.info(f"Alert suppressed: {alert.alert_id}")
                return alert
                
            # Store alert
            await self._store_alert(alert)
            
            # Apply alert rules
            await self._apply_alert_rules(alert)
            
            # Send notifications
            await self._send_notifications(alert)
            
            # Setup escalation if needed
            await self._setup_escalation(alert)
            
            # Update metrics
            self.metrics['alerts_generated'] += 1
            
            logger.info(f"Alert processed: {alert.alert_id} - {alert.severity}")
            return alert
            
        except Exception as e:
            logger.error(f"Alert processing failed: {e}")
            raise
            
    async def _create_alert_from_data(self, alert_data: Dict[str, Any]) -> Alert:
        """Create Alert object from incoming data"""
        alert_id = str(uuid.uuid4())
        
        # Extract basic fields
        title = alert_data.get('title', 'Security Alert')
        description = alert_data.get('description', 'Security event detected')
        severity = alert_data.get('severity', 'medium')
        category = alert_data.get('category', 'security_incident')
        source = alert_data.get('source', 'unknown')
        
        # Extract event information
        event_ids = alert_data.get('event_ids', [])
        if 'event_id' in alert_data:
            event_ids.append(alert_data['event_id'])
            
        # Extract affected assets
        affected_assets = alert_data.get('affected_assets', [])
        
        # Add assets from event data
        for field in ['host.name', 'source.ip', 'destination.ip', 'user.name']:
            value = self._get_nested_value(alert_data, field)
            if value and value not in affected_assets:
                affected_assets.append(value)
                
        # Extract indicators
        indicators = alert_data.get('indicators', {})
        
        # Add common indicators
        if 'threat' in alert_data:
            indicators['threat_detected'] = True
            indicators['threat_confidence'] = alert_data.get('threat', {}).get('confidence', 0)
            
        if 'ml_confidence' in alert_data:
            indicators['ml_confidence'] = alert_data['ml_confidence']
            
        # Create alert
        alert = Alert(
            alert_id=alert_id,
            title=title,
            description=description,
            severity=severity,
            category=category,
            source=source,
            event_ids=event_ids,
            affected_assets=affected_assets,
            indicators=indicators,
            metadata=alert_data.get('metadata', {}),
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
            status='new',
            child_alert_ids=[]
        )
        
        return alert
        
    async def _is_alert_suppressed(self, alert: Alert) -> bool:
        """Check if alert should be suppressed"""
        try:
            # Create suppression key based on alert characteristics
            suppression_key = self._create_suppression_key(alert)
            
            # Check if recently suppressed
            if self.redis_client:
                suppressed = await self.redis_client.get(f"suppressed:{suppression_key}")
                if suppressed:
                    return True
                    
            # Check for duplicate alerts
            if await self._is_duplicate_alert(alert):
                return True
                
            # Check custom suppression rules
            for rule_id, rule in self.alert_rules.items():
                if await self._matches_suppression_rule(alert, rule):
                    # Set suppression
                    if self.redis_client:
                        await self.redis_client.setex(
                            f"suppressed:{suppression_key}",
                            rule.suppression_window * 60,
                            "1"
                        )
                    return True
                    
            return False
            
        except Exception as e:
            logger.error(f"Suppression check failed: {e}")
            return False
            
    def _create_suppression_key(self, alert: Alert) -> str:
        """Create unique suppression key for alert"""
        key_components = [
            alert.severity,
            alert.category,
            alert.source,
            ','.join(sorted(alert.affected_assets[:3]))  # Limit to first 3 assets
        ]
        key_string = '|'.join(key_components)
        return hashlib.md5(key_string.encode()).hexdigest()
        
    async def _is_duplicate_alert(self, alert: Alert) -> bool:
        """Check if alert is a duplicate of recent alerts"""
        try:
            # Check recent alerts from cache
            for recent_alert in self.alert_cache:
                if (recent_alert['severity'] == alert.severity and
                    recent_alert['category'] == alert.category and
                    recent_alert['source'] == alert.source and
                    set(recent_alert['affected_assets']) == set(alert.affected_assets)):
                    
                    # Check time difference
                    created_time = datetime.fromisoformat(recent_alert['created_at'])
                    time_diff = (alert.created_at - created_time).total_seconds()
                    
                    if time_diff < 300:  # 5 minutes
                        return True
                        
            return False
            
        except Exception as e:
            logger.error(f"Duplicate check failed: {e}")
            return False
            
    async def _matches_suppression_rule(self, alert: Alert, rule: AlertRule) -> bool:
        """Check if alert matches suppression rule"""
        try:
            conditions = rule.conditions.get('suppression', {})
            
            # Check severity
            if 'severity' in conditions:
                if alert.severity not in conditions['severity']:
                    return False
                    
            # Check category
            if 'category' in conditions:
                if alert.category not in conditions['category']:
                    return False
                    
            # Check source
            if 'source' in conditions:
                if alert.source not in conditions['source']:
                    return False
                    
            # Check indicators
            if 'indicators' in conditions:
                for key, value in conditions['indicators'].items():
                    if alert.indicators.get(key) != value:
                        return False
                        
            return True
            
        except Exception as e:
            logger.error(f"Suppression rule check failed: {e}")
            return False
            
    async def _store_alert(self, alert: Alert):
        """Store alert in database"""
        try:
            if self.db_connection:
                cursor = self.db_connection.cursor()
                cursor.execute("""
                    INSERT INTO alerts 
                    (alert_id, title, description, severity, category, source, event_ids,
                     affected_assets, indicators, metadata, created_at, updated_at, status,
                     assigned_to, escalation_level, suppressed, parent_alert_id)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (
                    alert.alert_id, alert.title, alert.description, alert.severity,
                    alert.category, alert.source, json.dumps(alert.event_ids),
                    json.dumps(alert.affected_assets), json.dumps(alert.indicators),
                    json.dumps(alert.metadata), alert.created_at, alert.updated_at,
                    alert.status, alert.assigned_to, alert.escalation_level,
                    alert.suppressed, alert.parent_alert_id
                ))
                cursor.close()
                
            # Add to cache
            self.alert_cache.append({
                'alert_id': alert.alert_id,
                'severity': alert.severity,
                'category': alert.category,
                'source': alert.source,
                'affected_assets': alert.affected_assets,
                'created_at': alert.created_at.isoformat()
            })
            
            # Store in Redis for fast access
            if self.redis_client:
                await self.redis_client.setex(
                    f"alert:{alert.alert_id}",
                    86400,  # 24 hours
                    json.dumps(asdict(alert), default=str)
                )
                
        except Exception as e:
            logger.error(f"Alert storage failed: {e}")
            
    async def _apply_alert_rules(self, alert: Alert):
        """Apply alert rules to determine notification and escalation"""
        try:
            for rule_id, rule in self.alert_rules.items():
                if await self._matches_alert_rule(alert, rule):
                    # Update alert severity if rule specifies
                    if rule.severity and rule.severity != alert.severity:
                        alert.severity = rule.severity
                        
                    # Update category if rule specifies
                    if rule.category and rule.category != alert.category:
                        alert.category = rule.category
                        
                    # Store matched rule in metadata
                    alert.metadata['matched_rules'] = alert.metadata.get('matched_rules', [])
                    alert.metadata['matched_rules'].append(rule_id)
                    
                    logger.info(f"Alert {alert.alert_id} matched rule: {rule.name}")
                    
        except Exception as e:
            logger.error(f"Alert rule application failed: {e}")
            
    async def _matches_alert_rule(self, alert: Alert, rule: AlertRule) -> bool:
        """Check if alert matches rule conditions"""
        try:
            conditions = rule.conditions
            
            # Check severity
            if 'severity' in conditions:
                if alert.severity not in conditions['severity']:
                    return False
                    
            # Check category
            if 'category' in conditions:
                if alert.category not in conditions['category']:
                    return False
                    
            # Check source
            if 'source' in conditions:
                if alert.source not in conditions['source']:
                    return False
                    
            # Check indicators
            if 'indicators' in conditions:
                for key, expected_value in conditions['indicators'].items():
                    actual_value = alert.indicators.get(key)
                    if isinstance(expected_value, dict):
                        # Range or comparison check
                        if 'min' in expected_value and actual_value < expected_value['min']:
                            return False
                        if 'max' in expected_value and actual_value > expected_value['max']:
                            return False
                    else:
                        # Exact match
                        if actual_value != expected_value:
                            return False
                            
            # Check affected assets
            if 'affected_assets' in conditions:
                required_assets = conditions['affected_assets']
                if not any(asset in alert.affected_assets for asset in required_assets):
                    return False
                    
            return True
            
        except Exception as e:
            logger.error(f"Rule matching failed: {e}")
            return False
            
    async def _send_notifications(self, alert: Alert):
        """Send notifications through configured channels"""
        try:
            # Get notification channels for this alert
            channels_to_notify = await self._get_notification_channels(alert)
            
            notification_tasks = []
            for channel_name in channels_to_notify:
                if channel_name in self.notification_channels:
                    channel = self.notification_channels[channel_name]
                    
                    # Check rate limiting
                    if await self._check_rate_limit(channel):
                        task = self._send_channel_notification(alert, channel)
                        notification_tasks.append(task)
                    else:
                        logger.warning(f"Rate limit exceeded for channel: {channel_name}")
                        
            # Send notifications concurrently
            if notification_tasks:
                await asyncio.gather(*notification_tasks, return_exceptions=True)
                self.metrics['notifications_sent'] += len(notification_tasks)
                
        except Exception as e:
            logger.error(f"Notification sending failed: {e}")
            
    async def _get_notification_channels(self, alert: Alert) -> List[str]:
        """Get list of notification channels for alert"""
        channels = []
        
        # Check matched rules for channel specifications
        matched_rules = alert.metadata.get('matched_rules', [])
        for rule_id in matched_rules:
            if rule_id in self.alert_rules:
                rule = self.alert_rules[rule_id]
                channels.extend(rule.notification_channels)
                
        # Default channels based on severity
        if not channels:
            severity_channels = {
                'critical': ['email_critical', 'slack_security', 'pagerduty'],
                'high': ['email_security', 'slack_security'],
                'medium': ['email_security'],
                'low': ['slack_general']
            }
            channels = severity_channels.get(alert.severity, ['email_security'])
            
        return list(set(channels))  # Remove duplicates
        
    async def _check_rate_limit(self, channel: NotificationChannel) -> bool:
        """Check if channel is within rate limits"""
        now = time.time()
        limiter = self.rate_limiters[channel.name]
        
        # Reset counter if hour has passed
        if now >= limiter['reset_time']:
            limiter['count'] = 0
            limiter['reset_time'] = now + 3600
            
        # Check limit
        if limiter['count'] >= channel.rate_limit:
            return False
            
        limiter['count'] += 1
        return True
        
    async def _send_channel_notification(self, alert: Alert, channel: NotificationChannel):
        """Send notification to specific channel"""
        try:
            if channel.type == 'email':
                await self._send_email_notification(alert, channel)
            elif channel.type == 'slack':
                await self._send_slack_notification(alert, channel)
            elif channel.type == 'teams':
                await self._send_teams_notification(alert, channel)
            elif channel.type == 'webhook':
                await self._send_webhook_notification(alert, channel)
            elif channel.type == 'pagerduty':
                await self._send_pagerduty_notification(alert, channel)
            else:
                logger.warning(f"Unknown notification type: {channel.type}")
                
        except Exception as e:
            logger.error(f"Channel notification failed ({channel.name}): {e}")
            
    async def _send_email_notification(self, alert: Alert, channel: NotificationChannel):
        """Send email notification"""
        try:
            config = channel.config
            
            # Render template
            if self.template_env and 'email' in self._default_templates:
                template = self._default_templates['email']
                message_body = template.render(alert=alert)
            else:
                message_body = f"Alert: {alert.title}\nSeverity: {alert.severity}\n{alert.description}"
                
            # Create email message
            msg = MIMEMultipart()
            msg['From'] = config.get('from_address', 'siem@isectech.com')
            msg['To'] = ', '.join(config.get('to_addresses', []))
            msg['Subject'] = f"[SIEM Alert] {alert.severity.upper()} - {alert.title}"
            
            msg.attach(MIMEText(message_body, 'plain'))
            
            # Send email
            smtp_config = self.config.get('smtp', {})
            context = ssl.create_default_context()
            
            with smtplib.SMTP(smtp_config.get('host', 'localhost'), 
                            smtp_config.get('port', 587)) as server:
                if smtp_config.get('tls', True):
                    server.starttls(context=context)
                if smtp_config.get('username'):
                    server.login(smtp_config['username'], smtp_config['password'])
                    
                server.send_message(msg)
                
            logger.info(f"Email notification sent for alert: {alert.alert_id}")
            
        except Exception as e:
            logger.error(f"Email notification failed: {e}")
            
    async def _send_slack_notification(self, alert: Alert, channel: NotificationChannel):
        """Send Slack notification"""
        try:
            config = channel.config
            webhook_url = config.get('webhook_url')
            
            if not webhook_url:
                logger.error("Slack webhook URL not configured")
                return
                
            # Render template
            if self.template_env and 'slack' in self._default_templates:
                template = self._default_templates['slack']
                payload = json.loads(template.render(alert=alert))
            else:
                # Fallback simple message
                payload = {
                    "text": f"🚨 {alert.severity.upper()} Alert: {alert.title}",
                    "attachments": [
                        {
                            "color": self._get_slack_color(alert.severity),
                            "fields": [
                                {"title": "Severity", "value": alert.severity, "short": True},
                                {"title": "Category", "value": alert.category, "short": True},
                                {"title": "Description", "value": alert.description, "short": False}
                            ]
                        }
                    ]
                }
                
            # Send to Slack
            async with aiohttp.ClientSession() as session:
                async with session.post(webhook_url, json=payload) as response:
                    if response.status == 200:
                        logger.info(f"Slack notification sent for alert: {alert.alert_id}")
                    else:
                        logger.error(f"Slack notification failed: {response.status}")
                        
        except Exception as e:
            logger.error(f"Slack notification failed: {e}")
            
    async def _send_webhook_notification(self, alert: Alert, channel: NotificationChannel):
        """Send webhook notification"""
        try:
            config = channel.config
            webhook_url = config.get('url')
            
            if not webhook_url:
                logger.error("Webhook URL not configured")
                return
                
            # Prepare payload
            payload = {
                'alert': asdict(alert),
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'source': 'isectech-siem'
            }
            
            # Add custom fields
            if 'custom_fields' in config:
                payload.update(config['custom_fields'])
                
            # Send webhook
            headers = {'Content-Type': 'application/json'}
            if 'auth_header' in config:
                headers['Authorization'] = config['auth_header']
                
            async with aiohttp.ClientSession() as session:
                async with session.post(webhook_url, json=payload, headers=headers) as response:
                    if response.status in [200, 201, 202]:
                        logger.info(f"Webhook notification sent for alert: {alert.alert_id}")
                    else:
                        logger.error(f"Webhook notification failed: {response.status}")
                        
        except Exception as e:
            logger.error(f"Webhook notification failed: {e}")
            
    def _get_slack_color(self, severity: str) -> str:
        """Get Slack color for severity level"""
        colors = {
            'critical': '#FF0000',  # Red
            'high': '#FF8C00',      # Orange
            'medium': '#FFD700',    # Yellow
            'low': '#808080'        # Gray
        }
        return colors.get(severity, '#808080')
        
    async def _setup_escalation(self, alert: Alert):
        """Setup escalation timer for alert"""
        try:
            # Get escalation rules from matched rules
            escalation_rules = []
            matched_rules = alert.metadata.get('matched_rules', [])
            
            for rule_id in matched_rules:
                if rule_id in self.alert_rules:
                    rule = self.alert_rules[rule_id]
                    escalation_rules.extend(rule.escalation_rules)
                    
            if escalation_rules:
                # Schedule first escalation
                next_escalation = min(escalation_rules, key=lambda x: x.get('delay', 60))
                escalation_time = datetime.now(timezone.utc) + timedelta(
                    minutes=next_escalation.get('delay', 60)
                )
                
                self.escalation_timers[alert.alert_id] = {
                    'next_escalation': escalation_time,
                    'rules': escalation_rules,
                    'level': 0
                }
                
                logger.info(f"Escalation scheduled for alert: {alert.alert_id}")
                
        except Exception as e:
            logger.error(f"Escalation setup failed: {e}")
            
    async def _process_kafka_messages(self):
        """Process incoming Kafka messages"""
        if not self.kafka_consumer:
            return
            
        logger.info("Starting Kafka message processing for alerts")
        
        try:
            async for message in self.kafka_consumer:
                try:
                    alert_data = message.value
                    
                    # Add source topic to metadata
                    alert_data['metadata'] = alert_data.get('metadata', {})
                    alert_data['metadata']['source_topic'] = message.topic
                    
                    # Process the alert
                    await self.process_alert(alert_data)
                    
                except Exception as e:
                    logger.error(f"Failed to process Kafka message: {e}")
                    
        except Exception as e:
            logger.error(f"Kafka message processing failed: {e}")
            
    async def _process_escalations(self):
        """Process pending escalations"""
        while True:
            try:
                await asyncio.sleep(60)  # Check every minute
                
                current_time = datetime.now(timezone.utc)
                escalations_to_process = []
                
                # Find escalations that are due
                for alert_id, escalation in self.escalation_timers.items():
                    if current_time >= escalation['next_escalation']:
                        escalations_to_process.append(alert_id)
                        
                # Process due escalations
                for alert_id in escalations_to_process:
                    await self._escalate_alert(alert_id)
                    
            except Exception as e:
                logger.error(f"Escalation processing failed: {e}")
                await asyncio.sleep(60)
                
    async def _escalate_alert(self, alert_id: str):
        """Escalate an alert"""
        try:
            # Get alert from storage
            alert = await self._get_alert(alert_id)
            if not alert:
                logger.warning(f"Alert not found for escalation: {alert_id}")
                return
                
            # Check if alert is still unresolved
            if alert.status in ['resolved', 'closed']:
                logger.info(f"Alert already resolved, canceling escalation: {alert_id}")
                del self.escalation_timers[alert_id]
                return
                
            escalation = self.escalation_timers[alert_id]
            escalation['level'] += 1
            
            # Update alert escalation level
            alert.escalation_level = escalation['level']
            alert.updated_at = datetime.now(timezone.utc)
            
            # Send escalation notifications
            await self._send_escalation_notifications(alert)
            
            # Schedule next escalation if rules exist
            remaining_rules = [r for r in escalation['rules'] 
                             if r.get('level', 1) > escalation['level']]
            
            if remaining_rules:
                next_rule = min(remaining_rules, key=lambda x: x.get('delay', 60))
                escalation['next_escalation'] = datetime.now(timezone.utc) + timedelta(
                    minutes=next_rule.get('delay', 60)
                )
            else:
                # No more escalations
                del self.escalation_timers[alert_id]
                
            # Update alert in storage
            await self._update_alert(alert)
            
            self.metrics['escalations_triggered'] += 1
            logger.info(f"Alert escalated: {alert_id} to level {escalation['level']}")
            
        except Exception as e:
            logger.error(f"Alert escalation failed: {e}")
            
    async def _send_escalation_notifications(self, alert: Alert):
        """Send escalation notifications"""
        try:
            # Get escalation channels (typically higher priority)
            escalation_channels = ['email_critical', 'pagerduty', 'sms_oncall']
            
            # Update alert title to indicate escalation
            original_title = alert.title
            alert.title = f"[ESCALATED L{alert.escalation_level}] {original_title}"
            
            # Send notifications
            notification_tasks = []
            for channel_name in escalation_channels:
                if channel_name in self.notification_channels:
                    channel = self.notification_channels[channel_name]
                    if await self._check_rate_limit(channel):
                        task = self._send_channel_notification(alert, channel)
                        notification_tasks.append(task)
                        
            if notification_tasks:
                await asyncio.gather(*notification_tasks, return_exceptions=True)
                
            # Restore original title
            alert.title = original_title
            
        except Exception as e:
            logger.error(f"Escalation notification failed: {e}")
            
    async def _housekeeping_task(self):
        """Periodic housekeeping tasks"""
        while True:
            try:
                await asyncio.sleep(3600)  # Run every hour
                
                # Clean up old alerts from cache
                await self._cleanup_old_alerts()
                
                # Update metrics
                await self._update_metrics()
                
                # Clean up resolved escalations
                await self._cleanup_escalations()
                
            except Exception as e:
                logger.error(f"Housekeeping task failed: {e}")
                await asyncio.sleep(3600)
                
    async def _cleanup_old_alerts(self):
        """Clean up old alerts from memory"""
        try:
            cutoff_time = datetime.now(timezone.utc) - timedelta(hours=24)
            
            # Clean alert cache
            self.alert_cache = deque([
                alert for alert in self.alert_cache
                if datetime.fromisoformat(alert['created_at']) > cutoff_time
            ], maxlen=10000)
            
            # Clean escalation timers for resolved alerts
            resolved_alerts = []
            for alert_id in self.escalation_timers:
                alert = await self._get_alert(alert_id)
                if alert and alert.status in ['resolved', 'closed']:
                    resolved_alerts.append(alert_id)
                    
            for alert_id in resolved_alerts:
                del self.escalation_timers[alert_id]
                
            logger.info("Alert cleanup completed")
            
        except Exception as e:
            logger.error(f"Alert cleanup failed: {e}")
            
    async def _get_alert(self, alert_id: str) -> Optional[Alert]:
        """Get alert by ID"""
        try:
            # Try Redis first
            if self.redis_client:
                alert_data = await self.redis_client.get(f"alert:{alert_id}")
                if alert_data:
                    data = json.loads(alert_data)
                    return Alert(**data)
                    
            # Fall back to database
            if self.db_connection:
                cursor = self.db_connection.cursor()
                cursor.execute("SELECT * FROM alerts WHERE alert_id = %s", (alert_id,))
                row = cursor.fetchone()
                cursor.close()
                
                if row:
                    return Alert(
                        alert_id=row['alert_id'],
                        title=row['title'],
                        description=row['description'],
                        severity=row['severity'],
                        category=row['category'],
                        source=row['source'],
                        event_ids=json.loads(row['event_ids']),
                        affected_assets=json.loads(row['affected_assets']),
                        indicators=json.loads(row['indicators']),
                        metadata=json.loads(row['metadata']),
                        created_at=row['created_at'],
                        updated_at=row['updated_at'],
                        status=row['status'],
                        assigned_to=row['assigned_to'],
                        escalation_level=row['escalation_level'],
                        suppressed=row['suppressed'],
                        parent_alert_id=row['parent_alert_id'],
                        child_alert_ids=json.loads(row.get('child_alert_ids', '[]'))
                    )
                    
            return None
            
        except Exception as e:
            logger.error(f"Failed to get alert {alert_id}: {e}")
            return None
            
    async def _update_alert(self, alert: Alert):
        """Update alert in storage"""
        try:
            if self.db_connection:
                cursor = self.db_connection.cursor()
                cursor.execute("""
                    UPDATE alerts 
                    SET title = %s, description = %s, severity = %s, status = %s,
                        assigned_to = %s, escalation_level = %s, updated_at = %s,
                        metadata = %s
                    WHERE alert_id = %s
                """, (
                    alert.title, alert.description, alert.severity, alert.status,
                    alert.assigned_to, alert.escalation_level, alert.updated_at,
                    json.dumps(alert.metadata), alert.alert_id
                ))
                cursor.close()
                
            # Update Redis
            if self.redis_client:
                await self.redis_client.setex(
                    f"alert:{alert.alert_id}",
                    86400,
                    json.dumps(asdict(alert), default=str)
                )
                
        except Exception as e:
            logger.error(f"Alert update failed: {e}")
            
    def _get_nested_value(self, data: Dict[str, Any], key_path: str) -> Any:
        """Get nested value from dictionary using dot notation"""
        keys = key_path.split('.')
        value = data
        
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return None
                
        return value
        
    async def _update_metrics(self):
        """Update performance metrics"""
        try:
            # Reset hourly metrics
            for limiter in self.rate_limiters.values():
                if time.time() >= limiter['reset_time']:
                    limiter['count'] = 0
                    limiter['reset_time'] = time.time() + 3600
                    
            logger.info(f"Alert Manager Metrics: {self.metrics}")
            
        except Exception as e:
            logger.error(f"Metrics update failed: {e}")
            
    async def _cleanup_escalations(self):
        """Clean up old escalation timers"""
        try:
            current_time = datetime.now(timezone.utc)
            old_escalations = []
            
            for alert_id, escalation in self.escalation_timers.items():
                # Remove escalations older than 24 hours
                if (current_time - escalation['next_escalation']).total_seconds() > 86400:
                    old_escalations.append(alert_id)
                    
            for alert_id in old_escalations:
                del self.escalation_timers[alert_id]
                
        except Exception as e:
            logger.error(f"Escalation cleanup failed: {e}")
            
    def _sanitize_alert_for_logging(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        🔒 EMERGENCY SECURITY: Sanitize alert data for safe logging
        """
        sanitized = {}
        sensitive_fields = ['password', 'token', 'api_key', 'secret', 'credential', 'auth']
        
        for key, value in alert_data.items():
            if any(sensitive in key.lower() for sensitive in sensitive_fields):
                sanitized[key] = '***REDACTED***'
            elif isinstance(value, dict):
                sanitized[key] = self._sanitize_alert_for_logging(value)
            elif isinstance(value, str) and len(value) > 200:
                sanitized[key] = value[:200] + '...[TRUNCATED]'
            else:
                sanitized[key] = value
        
        return sanitized

    async def cleanup(self):
        """Cleanup resources"""
        try:
            if self.kafka_consumer:
                await self.kafka_consumer.stop()
            if self.kafka_producer:
                await self.kafka_producer.stop()
            if self.redis_client:
                await self.redis_client.close()
            if self.db_connection:
                self.db_connection.close()
            
            # 🔒 EMERGENCY SECURITY: Log hardening status on cleanup
            if EMERGENCY_HARDENING_ACTIVE:
                try:
                    status = emergency_siem_hardening.get_hardening_status()
                    logger.info(f"🔒 EMERGENCY SECURITY STATUS: {status}")
                except:
                    pass
                    
            logger.info("Alert Manager cleanup completed")
        except Exception as e:
            logger.error(f"Cleanup failed: {e}")

if __name__ == "__main__":
    # Example usage
    async def main():
        alert_manager = AlertManager("/path/to/alert_config.yaml")
        await alert_manager.initialize()
        
        # Example alert
        test_alert = {
            'title': 'Suspicious Login Activity',
            'description': 'Multiple failed login attempts detected',
            'severity': 'high',
            'category': 'security_incident',
            'source': 'correlation_engine',
            'event_id': 'test-001',
            'affected_assets': ['192.168.1.100', 'user@example.com'],
            'indicators': {'failed_logins': 15, 'ml_confidence': 0.85},
            'metadata': {'rule_name': 'Multiple Failed Logins'}
        }
        
        # Process alert
        alert = await alert_manager.process_alert(test_alert)
        print(f"Alert processed: {alert.alert_id}")
        
        await alert_manager.cleanup()
        
    # Run example
    # asyncio.run(main())