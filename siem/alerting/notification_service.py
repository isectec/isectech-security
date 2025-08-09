#!/usr/bin/env python3
"""
iSECTECH SIEM Notification Service
Advanced notification delivery system with multiple channels
Supports email, Slack, Teams, SMS, webhooks, and PagerDuty
"""

import asyncio
import json
import logging
import smtplib
import ssl
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
import aiohttp
import jinja2
from twilio.rest import Client as TwilioClient
from slack_sdk.web.async_client import AsyncWebClient
import yaml
import time
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class NotificationRequest:
    """Notification request data structure"""
    notification_id: str
    channel_name: str
    channel_type: str
    recipients: List[str]
    subject: str
    content: str
    priority: str
    alert_data: Dict[str, Any]
    template_name: Optional[str] = None
    attachments: List[Dict[str, Any]] = None
    metadata: Dict[str, Any] = None

@dataclass
class NotificationResult:
    """Notification delivery result"""
    notification_id: str
    channel_name: str
    success: bool
    delivery_time_ms: float
    error_message: Optional[str] = None
    external_id: Optional[str] = None  # External service message ID
    retry_count: int = 0

class NotificationService:
    """
    Advanced notification service for SIEM alerts
    Handles multiple notification channels with templates and delivery tracking
    """
    
    def __init__(self, config_path: str):
        self.config_path = Path(config_path)
        self.config = {}
        self.template_env = None
        self.notification_clients = {}
        self.delivery_stats = {
            'total_sent': 0,
            'successful_deliveries': 0,
            'failed_deliveries': 0,
            'avg_delivery_time': 0.0
        }
        
    async def initialize(self):
        """Initialize the notification service"""
        try:
            await self._load_config()
            await self._setup_templates()
            await self._initialize_clients()
            logger.info("Notification Service initialized successfully")
        except Exception as e:
            logger.error(f"Notification Service initialization failed: {e}")
            raise
            
    async def _load_config(self):
        """Load notification configuration"""
        try:
            with open(self.config_path, 'r') as f:
                self.config = yaml.safe_load(f)
        except Exception as e:
            logger.error(f"Failed to load config: {e}")
            # Use default configuration
            self.config = {
                'templates': {'path': '/opt/siem/templates'},
                'notification_channels': {},
                'smtp': {'host': 'localhost', 'port': 587}
            }
            
    async def _setup_templates(self):
        """Setup Jinja2 template environment"""
        try:
            templates_path = self.config.get('templates', {}).get('path', '/opt/siem/templates')
            
            if Path(templates_path).exists():
                self.template_env = jinja2.Environment(
                    loader=jinja2.FileSystemLoader(templates_path),
                    autoescape=jinja2.select_autoescape(['html', 'xml'])
                )
            else:
                # Create in-memory templates
                self.template_env = jinja2.Environment(loader=jinja2.DictLoader({}))
                await self._create_default_templates()
                
            logger.info("Templates initialized")
            
        except Exception as e:
            logger.error(f"Template setup failed: {e}")
            
    async def _create_default_templates(self):
        """Create default notification templates"""
        # Default email template
        email_template = """
Subject: {{ subject }}

{% if alert_data %}
SECURITY ALERT NOTIFICATION
============================

Alert ID: {{ alert_data.alert_id }}
Severity: {{ alert_data.severity | upper }}
Category: {{ alert_data.category | title }}
Created: {{ alert_data.created_at }}

Description:
{{ alert_data.description }}

{% if alert_data.affected_assets %}
Affected Assets:
{% for asset in alert_data.affected_assets %}
- {{ asset }}
{% endfor %}
{% endif %}

{% if alert_data.indicators %}
Key Indicators:
{% for key, value in alert_data.indicators.items() %}
- {{ key | title }}: {{ value }}
{% endfor %}
{% endif %}

Recommended Actions:
{% if alert_data.recommended_actions %}
{% for action in alert_data.recommended_actions %}
- {{ action }}
{% endfor %}
{% else %}
- Review alert details and investigate as necessary
- Correlate with other security events
- Document findings and response actions
{% endif %}

{% else %}
{{ content }}
{% endif %}

---
This alert was generated by iSECTECH SIEM System
Timestamp: {{ timestamp }}
        """
        
        # Default Slack template
        slack_template = """
{
    "blocks": [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": "🚨 {{ alert_data.severity | upper }} Alert: {{ alert_data.title }}"
            }
        },
        {
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": "*Alert ID:*\\n{{ alert_data.alert_id }}"
                },
                {
                    "type": "mrkdwn",
                    "text": "*Severity:*\\n{{ alert_data.severity | upper }}"
                },
                {
                    "type": "mrkdwn",
                    "text": "*Category:*\\n{{ alert_data.category | title }}"
                },
                {
                    "type": "mrkdwn",
                    "text": "*Source:*\\n{{ alert_data.source }}"
                }
            ]
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "*Description:*\\n{{ alert_data.description }}"
            }
        },
        {% if alert_data.affected_assets %}
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "*Affected Assets:*\\n{{ alert_data.affected_assets | join(', ') }}"
            }
        },
        {% endif %}
        {
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {
                        "type": "plain_text",
                        "text": "Acknowledge"
                    },
                    "style": "primary",
                    "value": "ack_{{ alert_data.alert_id }}",
                    "action_id": "acknowledge_alert"
                },
                {
                    "type": "button",
                    "text": {
                        "type": "plain_text",
                        "text": "Investigate"
                    },
                    "value": "investigate_{{ alert_data.alert_id }}",
                    "action_id": "investigate_alert"
                },
                {
                    "type": "button",
                    "text": {
                        "type": "plain_text",
                        "text": "View Details"
                    },
                    "url": "{{ dashboard_url }}/alerts/{{ alert_data.alert_id }}",
                    "action_id": "view_alert"
                }
            ]
        }
    ]
}
        """
        
        # Default Teams template
        teams_template = """
{
    "@type": "MessageCard",
    "@context": "http://schema.org/extensions",
    "summary": "{{ alert_data.severity | upper }} Alert: {{ alert_data.title }}",
    "themeColor": "{{ color }}",
    "sections": [
        {
            "activityTitle": "🚨 {{ alert_data.severity | upper }} Security Alert",
            "activitySubtitle": "{{ alert_data.title }}",
            "activityImage": "https://example.com/security-icon.png",
            "facts": [
                {
                    "name": "Alert ID",
                    "value": "{{ alert_data.alert_id }}"
                },
                {
                    "name": "Severity",
                    "value": "{{ alert_data.severity | upper }}"
                },
                {
                    "name": "Category",
                    "value": "{{ alert_data.category | title }}"
                },
                {
                    "name": "Source",
                    "value": "{{ alert_data.source }}"
                },
                {
                    "name": "Created",
                    "value": "{{ alert_data.created_at }}"
                }
            ],
            "markdown": true,
            "text": "{{ alert_data.description }}"
        }
    ],
    "potentialAction": [
        {
            "@type": "OpenUri",
            "name": "View Alert Details",
            "targets": [
                {
                    "os": "default",
                    "uri": "{{ dashboard_url }}/alerts/{{ alert_data.alert_id }}"
                }
            ]
        }
    ]
}
        """
        
        # Store templates
        self.default_templates = {
            'email': jinja2.Template(email_template),
            'slack': jinja2.Template(slack_template),
            'teams': jinja2.Template(teams_template)
        }
        
    async def _initialize_clients(self):
        """Initialize notification clients"""
        try:
            # Initialize Slack client
            slack_config = self.config.get('integrations', {}).get('chat_platforms', {}).get('slack', {})
            if slack_config.get('bot_token'):
                self.notification_clients['slack'] = AsyncWebClient(
                    token=slack_config['bot_token']
                )
                
            # Initialize Twilio client
            twilio_config = self._get_twilio_config()
            if twilio_config:
                self.notification_clients['twilio'] = TwilioClient(
                    twilio_config['account_sid'],
                    twilio_config['auth_token']
                )
                
            logger.info("Notification clients initialized")
            
        except Exception as e:
            logger.error(f"Client initialization failed: {e}")
            
    def _get_twilio_config(self) -> Optional[Dict[str, str]]:
        """Get Twilio configuration from notification channels"""
        for channel in self.config.get('notification_channels', {}).values():
            if channel.get('type') == 'sms' and channel.get('config', {}).get('provider') == 'twilio':
                config = channel['config']
                if all(key in config for key in ['account_sid', 'auth_token']):
                    return config
        return None
        
    async def send_notification(self, request: NotificationRequest) -> NotificationResult:
        """Send notification through specified channel"""
        start_time = time.time()
        
        try:
            # Get channel configuration
            channel_config = self.config.get('notification_channels', {}).get(request.channel_name)
            if not channel_config:
                raise ValueError(f"Channel not found: {request.channel_name}")
                
            if not channel_config.get('enabled', True):
                raise ValueError(f"Channel disabled: {request.channel_name}")
                
            # Route to appropriate handler
            result = None
            if request.channel_type == 'email':
                result = await self._send_email(request, channel_config)
            elif request.channel_type == 'slack':
                result = await self._send_slack(request, channel_config)
            elif request.channel_type == 'teams':
                result = await self._send_teams(request, channel_config)
            elif request.channel_type == 'sms':
                result = await self._send_sms(request, channel_config)
            elif request.channel_type == 'webhook':
                result = await self._send_webhook(request, channel_config)
            elif request.channel_type == 'pagerduty':
                result = await self._send_pagerduty(request, channel_config)
            else:
                raise ValueError(f"Unsupported channel type: {request.channel_type}")
                
            # Calculate delivery time
            delivery_time = (time.time() - start_time) * 1000
            
            if result:
                result.delivery_time_ms = delivery_time
                
                # Update stats
                self.delivery_stats['total_sent'] += 1
                if result.success:
                    self.delivery_stats['successful_deliveries'] += 1
                else:
                    self.delivery_stats['failed_deliveries'] += 1
                    
                # Update average delivery time
                self._update_avg_delivery_time(delivery_time)
                
                return result
            else:
                return NotificationResult(
                    notification_id=request.notification_id,
                    channel_name=request.channel_name,
                    success=False,
                    delivery_time_ms=delivery_time,
                    error_message="No result returned from handler"
                )
                
        except Exception as e:
            delivery_time = (time.time() - start_time) * 1000
            logger.error(f"Notification failed ({request.channel_name}): {e}")
            
            self.delivery_stats['total_sent'] += 1
            self.delivery_stats['failed_deliveries'] += 1
            
            return NotificationResult(
                notification_id=request.notification_id,
                channel_name=request.channel_name,
                success=False,
                delivery_time_ms=delivery_time,
                error_message=str(e)
            )
            
    async def _send_email(self, request: NotificationRequest, config: Dict[str, Any]) -> NotificationResult:
        """Send email notification"""
        try:
            email_config = config['config']
            
            # Render email content
            content = await self._render_template(request, 'email')
            
            # Parse subject and body from content
            lines = content.strip().split('\n')
            subject_line = next((line for line in lines if line.startswith('Subject:')), None)
            
            if subject_line:
                subject = subject_line.replace('Subject:', '').strip()
                body_start = lines.index(subject_line) + 1
                body = '\n'.join(lines[body_start:]).strip()
            else:
                subject = request.subject or f"SIEM Alert: {request.alert_data.get('title', 'Security Alert')}"
                body = content
                
            # Create email message
            msg = MIMEMultipart()
            msg['From'] = email_config.get('from_address', 'siem@isectech.com')
            msg['To'] = ', '.join(request.recipients or email_config.get('to_addresses', []))
            msg['Subject'] = subject
            
            if email_config.get('reply_to'):
                msg['Reply-To'] = email_config['reply_to']
                
            # Add body
            msg.attach(MIMEText(body, 'plain'))
            
            # Add attachments if any
            if request.attachments:
                for attachment in request.attachments:
                    part = MIMEBase('application', 'octet-stream')
                    part.set_payload(attachment['data'])
                    encoders.encode_base64(part)
                    part.add_header(
                        'Content-Disposition',
                        f'attachment; filename= {attachment["filename"]}'
                    )
                    msg.attach(part)
                    
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
                
            logger.info(f"Email sent successfully: {request.notification_id}")
            
            return NotificationResult(
                notification_id=request.notification_id,
                channel_name=request.channel_name,
                success=True,
                delivery_time_ms=0.0  # Will be set by caller
            )
            
        except Exception as e:
            logger.error(f"Email sending failed: {e}")
            return NotificationResult(
                notification_id=request.notification_id,
                channel_name=request.channel_name,
                success=False,
                delivery_time_ms=0.0,
                error_message=str(e)
            )
            
    async def _send_slack(self, request: NotificationRequest, config: Dict[str, Any]) -> NotificationResult:
        """Send Slack notification"""
        try:
            slack_config = config['config']
            
            # Use webhook or bot API
            if 'webhook_url' in slack_config:
                return await self._send_slack_webhook(request, slack_config)
            elif 'slack' in self.notification_clients:
                return await self._send_slack_api(request, slack_config)
            else:
                raise ValueError("No Slack configuration available")
                
        except Exception as e:
            logger.error(f"Slack sending failed: {e}")
            return NotificationResult(
                notification_id=request.notification_id,
                channel_name=request.channel_name,
                success=False,
                delivery_time_ms=0.0,
                error_message=str(e)
            )
            
    async def _send_slack_webhook(self, request: NotificationRequest, config: Dict[str, str]) -> NotificationResult:
        """Send Slack notification via webhook"""
        try:
            webhook_url = config['webhook_url']
            
            # Render Slack message
            content = await self._render_template(request, 'slack')
            
            # Parse JSON content
            if content.strip().startswith('{'):
                payload = json.loads(content)
            else:
                # Fallback to simple text message
                payload = {
                    "text": f"🚨 {request.alert_data.get('severity', 'UNKNOWN').upper()} Alert",
                    "attachments": [
                        {
                            "color": self._get_slack_color(request.alert_data.get('severity', 'medium')),
                            "fields": [
                                {
                                    "title": "Alert",
                                    "value": request.alert_data.get('title', 'Security Alert'),
                                    "short": False
                                },
                                {
                                    "title": "Description",
                                    "value": request.content or request.alert_data.get('description', 'No description'),
                                    "short": False
                                }
                            ]
                        }
                    ]
                }
                
            # Add configuration overrides
            if config.get('channel'):
                payload['channel'] = config['channel']
            if config.get('username'):
                payload['username'] = config['username']
            if config.get('icon_emoji'):
                payload['icon_emoji'] = config['icon_emoji']
                
            # Send to Slack
            async with aiohttp.ClientSession() as session:
                async with session.post(webhook_url, json=payload) as response:
                    if response.status == 200:
                        logger.info(f"Slack webhook sent successfully: {request.notification_id}")
                        return NotificationResult(
                            notification_id=request.notification_id,
                            channel_name=request.channel_name,
                            success=True,
                            delivery_time_ms=0.0
                        )
                    else:
                        error_text = await response.text()
                        raise Exception(f"Slack API error {response.status}: {error_text}")
                        
        except Exception as e:
            raise Exception(f"Slack webhook failed: {e}")
            
    async def _send_slack_api(self, request: NotificationRequest, config: Dict[str, str]) -> NotificationResult:
        """Send Slack notification via Bot API"""
        try:
            client = self.notification_clients['slack']
            
            # Render content
            content = await self._render_template(request, 'slack')
            
            # Determine channel
            channel = config.get('channel', '#general')
            
            # Send message
            if content.strip().startswith('{'):
                # JSON blocks format
                blocks = json.loads(content).get('blocks', [])
                response = await client.chat_postMessage(
                    channel=channel,
                    blocks=blocks,
                    username=config.get('username', 'SIEM Bot'),
                    icon_emoji=config.get('icon_emoji', ':warning:')
                )
            else:
                # Simple text message
                response = await client.chat_postMessage(
                    channel=channel,
                    text=content,
                    username=config.get('username', 'SIEM Bot'),
                    icon_emoji=config.get('icon_emoji', ':warning:')
                )
                
            if response['ok']:
                logger.info(f"Slack API message sent successfully: {request.notification_id}")
                return NotificationResult(
                    notification_id=request.notification_id,
                    channel_name=request.channel_name,
                    success=True,
                    delivery_time_ms=0.0,
                    external_id=response.get('ts')
                )
            else:
                raise Exception(f"Slack API error: {response.get('error', 'Unknown error')}")
                
        except Exception as e:
            raise Exception(f"Slack API failed: {e}")
            
    async def _send_teams(self, request: NotificationRequest, config: Dict[str, Any]) -> NotificationResult:
        """Send Microsoft Teams notification"""
        try:
            teams_config = config['config']
            webhook_url = teams_config.get('webhook_url')
            
            if not webhook_url:
                raise ValueError("Teams webhook URL not configured")
                
            # Render Teams message
            content = await self._render_template(request, 'teams')
            
            # Parse JSON content or create simple card
            if content.strip().startswith('{'):
                payload = json.loads(content)
            else:
                # Create simple adaptive card
                color = self._get_teams_color(request.alert_data.get('severity', 'medium'))
                payload = {
                    "@type": "MessageCard",
                    "@context": "http://schema.org/extensions",
                    "summary": f"{request.alert_data.get('severity', 'UNKNOWN').upper()} Alert",
                    "themeColor": color,
                    "sections": [
                        {
                            "activityTitle": f"🚨 {request.alert_data.get('severity', 'UNKNOWN').upper()} Security Alert",
                            "activitySubtitle": request.alert_data.get('title', 'Security Alert'),
                            "text": request.content or request.alert_data.get('description', 'No description')
                        }
                    ]
                }
                
            # Send to Teams
            async with aiohttp.ClientSession() as session:
                async with session.post(webhook_url, json=payload) as response:
                    if response.status == 200:
                        logger.info(f"Teams notification sent successfully: {request.notification_id}")
                        return NotificationResult(
                            notification_id=request.notification_id,
                            channel_name=request.channel_name,
                            success=True,
                            delivery_time_ms=0.0
                        )
                    else:
                        error_text = await response.text()
                        raise Exception(f"Teams API error {response.status}: {error_text}")
                        
        except Exception as e:
            logger.error(f"Teams sending failed: {e}")
            return NotificationResult(
                notification_id=request.notification_id,
                channel_name=request.channel_name,
                success=False,
                delivery_time_ms=0.0,
                error_message=str(e)
            )
            
    async def _send_sms(self, request: NotificationRequest, config: Dict[str, Any]) -> NotificationResult:
        """Send SMS notification"""
        try:
            sms_config = config['config']
            
            if sms_config.get('provider') == 'twilio':
                return await self._send_twilio_sms(request, sms_config)
            else:
                raise ValueError(f"Unsupported SMS provider: {sms_config.get('provider')}")
                
        except Exception as e:
            logger.error(f"SMS sending failed: {e}")
            return NotificationResult(
                notification_id=request.notification_id,
                channel_name=request.channel_name,
                success=False,
                delivery_time_ms=0.0,
                error_message=str(e)
            )
            
    async def _send_twilio_sms(self, request: NotificationRequest, config: Dict[str, str]) -> NotificationResult:
        """Send SMS via Twilio"""
        try:
            if 'twilio' not in self.notification_clients:
                raise ValueError("Twilio client not initialized")
                
            client = self.notification_clients['twilio']
            
            # Prepare message content
            if config.get('message_template'):
                # Use custom template
                template = jinja2.Template(config['message_template'])
                message_body = template.render(alert=request.alert_data)
            else:
                # Default SMS format
                message_body = f"SIEM Alert: {request.alert_data.get('severity', 'UNKNOWN').upper()} - {request.alert_data.get('title', 'Security Alert')}"
                
            # Truncate if too long (SMS limit is typically 160 chars)
            if len(message_body) > 160:
                message_body = message_body[:157] + "..."
                
            # Send to all recipients
            from_number = config.get('from_number')
            to_numbers = request.recipients or config.get('to_numbers', [])
            
            results = []
            for to_number in to_numbers:
                try:
                    message = client.messages.create(
                        body=message_body,
                        from_=from_number,
                        to=to_number
                    )
                    results.append({'number': to_number, 'sid': message.sid, 'success': True})
                except Exception as e:
                    results.append({'number': to_number, 'error': str(e), 'success': False})
                    
            # Check if any succeeded
            successful = any(r['success'] for r in results)
            
            if successful:
                logger.info(f"SMS sent successfully: {request.notification_id}")
                return NotificationResult(
                    notification_id=request.notification_id,
                    channel_name=request.channel_name,
                    success=True,
                    delivery_time_ms=0.0,
                    external_id=','.join([r.get('sid', '') for r in results if r['success']])
                )
            else:
                errors = [r.get('error', 'Unknown error') for r in results if not r['success']]
                raise Exception(f"All SMS sends failed: {'; '.join(errors)}")
                
        except Exception as e:
            raise Exception(f"Twilio SMS failed: {e}")
            
    async def _send_webhook(self, request: NotificationRequest, config: Dict[str, Any]) -> NotificationResult:
        """Send webhook notification"""
        try:
            webhook_config = config['config']
            url = webhook_config.get('url')
            
            if not url:
                raise ValueError("Webhook URL not configured")
                
            # Prepare payload
            if request.template_name:
                content = await self._render_template(request, request.template_name)
                if content.strip().startswith('{'):
                    payload = json.loads(content)
                else:
                    payload = {'message': content}
            else:
                # Default webhook payload
                payload = {
                    'notification_id': request.notification_id,
                    'alert_data': request.alert_data,
                    'subject': request.subject,
                    'content': request.content,
                    'priority': request.priority,
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                    'source': 'isectech-siem'
                }
                
            # Add custom fields
            if webhook_config.get('custom_fields'):
                payload.update(webhook_config['custom_fields'])
                
            # Prepare headers
            headers = {'Content-Type': 'application/json'}
            if webhook_config.get('headers'):
                headers.update(webhook_config['headers'])
                
            # Send webhook
            method = webhook_config.get('method', 'POST').upper()
            timeout = webhook_config.get('timeout', 10)
            
            async with aiohttp.ClientSession() as session:
                async with session.request(
                    method, url, json=payload, headers=headers, timeout=timeout
                ) as response:
                    if response.status in [200, 201, 202]:
                        logger.info(f"Webhook sent successfully: {request.notification_id}")
                        return NotificationResult(
                            notification_id=request.notification_id,
                            channel_name=request.channel_name,
                            success=True,
                            delivery_time_ms=0.0
                        )
                    else:
                        error_text = await response.text()
                        raise Exception(f"Webhook error {response.status}: {error_text}")
                        
        except Exception as e:
            logger.error(f"Webhook sending failed: {e}")
            return NotificationResult(
                notification_id=request.notification_id,
                channel_name=request.channel_name,
                success=False,
                delivery_time_ms=0.0,
                error_message=str(e)
            )
            
    async def _send_pagerduty(self, request: NotificationRequest, config: Dict[str, Any]) -> NotificationResult:
        """Send PagerDuty notification"""
        try:
            pd_config = config['config']
            integration_key = pd_config.get('integration_key')
            api_url = pd_config.get('api_url', 'https://events.pagerduty.com/v2/enqueue')
            
            if not integration_key:
                raise ValueError("PagerDuty integration key not configured")
                
            # Map severity to PagerDuty severity
            severity_mapping = pd_config.get('severity_mapping', {
                'critical': 'critical',
                'high': 'error',
                'medium': 'warning',
                'low': 'info'
            })
            
            alert_severity = request.alert_data.get('severity', 'medium')
            pd_severity = severity_mapping.get(alert_severity, 'warning')
            
            # Prepare PagerDuty event
            payload = {
                'routing_key': integration_key,
                'event_action': 'trigger',
                'dedup_key': f"siem-alert-{request.alert_data.get('alert_id', request.notification_id)}",
                'payload': {
                    'summary': request.subject or request.alert_data.get('title', 'SIEM Security Alert'),
                    'source': 'iSECTECH SIEM',
                    'severity': pd_severity,
                    'component': request.alert_data.get('source', 'SIEM'),
                    'group': request.alert_data.get('category', 'security'),
                    'class': request.alert_data.get('category', 'security_incident'),
                    'custom_details': {
                        'alert_id': request.alert_data.get('alert_id'),
                        'affected_assets': request.alert_data.get('affected_assets', []),
                        'indicators': request.alert_data.get('indicators', {}),
                        'description': request.content or request.alert_data.get('description')
                    }
                }
            }
            
            # Send to PagerDuty
            async with aiohttp.ClientSession() as session:
                async with session.post(api_url, json=payload) as response:
                    if response.status == 202:
                        response_data = await response.json()
                        logger.info(f"PagerDuty notification sent successfully: {request.notification_id}")
                        return NotificationResult(
                            notification_id=request.notification_id,
                            channel_name=request.channel_name,
                            success=True,
                            delivery_time_ms=0.0,
                            external_id=response_data.get('dedup_key')
                        )
                    else:
                        error_text = await response.text()
                        raise Exception(f"PagerDuty API error {response.status}: {error_text}")
                        
        except Exception as e:
            logger.error(f"PagerDuty sending failed: {e}")
            return NotificationResult(
                notification_id=request.notification_id,
                channel_name=request.channel_name,
                success=False,
                delivery_time_ms=0.0,
                error_message=str(e)
            )
            
    async def _render_template(self, request: NotificationRequest, template_type: str) -> str:
        """Render notification template"""
        try:
            template_name = request.template_name or f"{template_type}_default"
            
            # Try to get template from environment
            try:
                template = self.template_env.get_template(f"{template_name}.j2")
            except jinja2.exceptions.TemplateNotFound:
                # Fall back to default templates
                if template_type in self.default_templates:
                    template = self.default_templates[template_type]
                else:
                    # Create minimal template
                    template = jinja2.Template("{{ content }}")
                    
            # Prepare template context
            context = {
                'alert_data': request.alert_data,
                'subject': request.subject,
                'content': request.content,
                'priority': request.priority,
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'dashboard_url': self.config.get('dashboard_url', 'https://siem.isectech.com'),
                'color': self._get_color_for_severity(request.alert_data.get('severity', 'medium'), template_type)
            }
            
            # Add metadata
            if request.metadata:
                context.update(request.metadata)
                
            # Render template
            rendered = template.render(**context)
            return rendered
            
        except Exception as e:
            logger.error(f"Template rendering failed: {e}")
            # Return fallback content
            return f"Alert: {request.alert_data.get('title', 'Security Alert')}\n{request.content}"
            
    def _get_color_for_severity(self, severity: str, template_type: str) -> str:
        """Get color code for severity level based on template type"""
        if template_type == 'slack':
            return self._get_slack_color(severity)
        elif template_type == 'teams':
            return self._get_teams_color(severity)
        else:
            return '#808080'  # Default gray
            
    def _get_slack_color(self, severity: str) -> str:
        """Get Slack color for severity level"""
        colors = {
            'critical': 'danger',    # Red
            'high': 'warning',       # Orange  
            'medium': 'warning',     # Orange
            'low': 'good'           # Green
        }
        return colors.get(severity.lower(), 'warning')
        
    def _get_teams_color(self, severity: str) -> str:
        """Get Teams color for severity level"""
        colors = {
            'critical': '#FF0000',  # Red
            'high': '#FF8C00',      # Orange
            'medium': '#FFD700',    # Yellow
            'low': '#808080'        # Gray
        }
        return colors.get(severity.lower(), '#808080')
        
    def _update_avg_delivery_time(self, delivery_time: float):
        """Update average delivery time"""
        total_deliveries = self.delivery_stats['successful_deliveries'] + self.delivery_stats['failed_deliveries']
        if total_deliveries > 0:
            current_avg = self.delivery_stats['avg_delivery_time']
            self.delivery_stats['avg_delivery_time'] = (
                (current_avg * (total_deliveries - 1) + delivery_time) / total_deliveries
            )
            
    async def send_batch_notifications(self, requests: List[NotificationRequest]) -> List[NotificationResult]:
        """Send multiple notifications concurrently"""
        try:
            # Create tasks for concurrent execution
            tasks = [self.send_notification(request) for request in requests]
            
            # Execute concurrently
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Process results
            processed_results = []
            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    logger.error(f"Batch notification failed: {result}")
                    processed_results.append(NotificationResult(
                        notification_id=requests[i].notification_id,
                        channel_name=requests[i].channel_name,
                        success=False,
                        delivery_time_ms=0.0,
                        error_message=str(result)
                    ))
                else:
                    processed_results.append(result)
                    
            return processed_results
            
        except Exception as e:
            logger.error(f"Batch notification processing failed: {e}")
            return []
            
    def get_delivery_stats(self) -> Dict[str, Any]:
        """Get notification delivery statistics"""
        return self.delivery_stats.copy()
        
    async def test_channel(self, channel_name: str) -> NotificationResult:
        """Test notification channel with a simple test message"""
        try:
            # Create test notification request
            test_request = NotificationRequest(
                notification_id=f"test-{int(time.time())}",
                channel_name=channel_name,
                channel_type=self.config.get('notification_channels', {}).get(channel_name, {}).get('type', 'unknown'),
                recipients=[],
                subject="SIEM Test Notification",
                content="This is a test notification from iSECTECH SIEM system.",
                priority="low",
                alert_data={
                    'alert_id': 'test-alert',
                    'title': 'Test Alert',
                    'description': 'This is a test alert for notification channel verification.',
                    'severity': 'low',
                    'category': 'system',
                    'source': 'notification_service',
                    'created_at': datetime.now(timezone.utc).isoformat(),
                    'affected_assets': [],
                    'indicators': {},
                    'recommended_actions': ['This is a test - no action required']
                }
            )
            
            # Send test notification
            result = await self.send_notification(test_request)
            
            if result.success:
                logger.info(f"Channel test successful: {channel_name}")
            else:
                logger.warning(f"Channel test failed: {channel_name} - {result.error_message}")
                
            return result
            
        except Exception as e:
            logger.error(f"Channel test error: {e}")
            return NotificationResult(
                notification_id=f"test-{int(time.time())}",
                channel_name=channel_name,
                success=False,
                delivery_time_ms=0.0,
                error_message=str(e)
            )

if __name__ == "__main__":
    # Example usage
    async def main():
        service = NotificationService("/path/to/alert_config.yaml")
        await service.initialize()
        
        # Test notification
        test_request = NotificationRequest(
            notification_id="test-001",
            channel_name="email_security",
            channel_type="email",
            recipients=["test@example.com"],
            subject="Test Alert",
            content="This is a test notification",
            priority="medium",
            alert_data={
                'alert_id': 'test-001',
                'title': 'Test Security Alert',
                'description': 'Test alert description',
                'severity': 'medium',
                'category': 'security_incident',
                'source': 'test',
                'created_at': datetime.now(timezone.utc).isoformat(),
                'affected_assets': ['test-asset'],
                'indicators': {'test_indicator': 'value'}
            }
        )
        
        result = await service.send_notification(test_request)
        print(f"Notification result: {result.success}")
        
    # Run example
    # asyncio.run(main())