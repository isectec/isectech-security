"""
Workflow and Response Automation for Identity and Access Analytics
================================================================

Production-grade automated response system that orchestrates security workflows,
manages incident response, and provides intelligent automation for identity and
access management events and threats.

Copyright (c) 2024 iSecTech. All Rights Reserved.
"""

import asyncio
import logging
import json
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple, Set, Union, Callable, Awaitable
from dataclasses import dataclass, field, asdict
from enum import Enum, IntEnum
from collections import defaultdict, deque
import aioredis
import sqlite3
import hashlib
import hmac
import uuid
import traceback
import threading
from concurrent.futures import ThreadPoolExecutor
import aiohttp
import ssl
import certifi
from cryptography.fernet import Fernet
import yaml
import jinja2
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class WorkflowStatus(Enum):
    """Workflow execution status"""
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"

class ActionType(Enum):
    """Types of automated actions"""
    USER_DISABLE = "user_disable"
    USER_SUSPEND = "user_suspend"
    FORCE_PASSWORD_RESET = "force_password_reset"
    REVOKE_SESSION = "revoke_session"
    LOCK_ACCOUNT = "lock_account"
    QUARANTINE_DEVICE = "quarantine_device"
    ISOLATE_NETWORK = "isolate_network"
    BLOCK_IP = "block_ip"
    EMAIL_ALERT = "email_alert"
    SLACK_NOTIFICATION = "slack_notification"
    TEAMS_NOTIFICATION = "teams_notification"
    TICKET_CREATION = "ticket_creation"
    PRIVILEGE_ESCALATION_ALERT = "privilege_escalation_alert"
    COMPLIANCE_VIOLATION_REPORT = "compliance_violation_report"
    FORENSIC_CAPTURE = "forensic_capture"
    ACCESS_REVIEW_TRIGGER = "access_review_trigger"
    POLICY_VIOLATION_LOG = "policy_violation_log"
    SECURITY_TEAM_ESCALATION = "security_team_escalation"

class TriggerType(Enum):
    """Workflow trigger types"""
    RISK_SCORE_THRESHOLD = "risk_score_threshold"
    ANOMALY_DETECTED = "anomaly_detected"
    POLICY_VIOLATION = "policy_violation"
    THREAT_DETECTED = "threat_detected"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    SUSPICIOUS_LOGIN = "suspicious_login"
    DATA_EXFILTRATION = "data_exfiltration"
    COMPLIANCE_VIOLATION = "compliance_violation"
    MULTIPLE_FAILED_LOGINS = "multiple_failed_logins"
    IMPOSSIBLE_TRAVEL = "impossible_travel"
    NEW_DEVICE_LOGIN = "new_device_login"
    OFF_HOURS_ACCESS = "off_hours_access"
    BULK_DATA_ACCESS = "bulk_data_access"
    ADMIN_ACTION = "admin_action"
    SCHEDULED = "scheduled"

class Priority(IntEnum):
    """Priority levels"""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4
    EMERGENCY = 5

class ApprovalStatus(Enum):
    """Approval status for actions requiring human approval"""
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"

@dataclass
class WorkflowAction:
    """Individual workflow action"""
    id: str
    action_type: ActionType
    parameters: Dict[str, Any]
    timeout_seconds: int
    retry_count: int
    max_retries: int
    requires_approval: bool
    approval_timeout: Optional[int]
    condition: Optional[str]  # Python expression for conditional execution
    on_success: Optional[List[str]]  # Next action IDs on success
    on_failure: Optional[List[str]]  # Next action IDs on failure
    status: WorkflowStatus = WorkflowStatus.PENDING
    error_message: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    approval_status: Optional[ApprovalStatus] = None
    approved_by: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation"""
        return {
            'id': self.id,
            'action_type': self.action_type.value,
            'parameters': self.parameters,
            'timeout_seconds': self.timeout_seconds,
            'retry_count': self.retry_count,
            'max_retries': self.max_retries,
            'requires_approval': self.requires_approval,
            'approval_timeout': self.approval_timeout,
            'condition': self.condition,
            'on_success': self.on_success,
            'on_failure': self.on_failure,
            'status': self.status.value,
            'error_message': self.error_message,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'approval_status': self.approval_status.value if self.approval_status else None,
            'approved_by': self.approved_by
        }

@dataclass
class WorkflowTemplate:
    """Workflow template definition"""
    id: str
    name: str
    description: str
    trigger_type: TriggerType
    trigger_conditions: Dict[str, Any]
    actions: List[WorkflowAction]
    priority: Priority
    enabled: bool
    created_by: str
    created_at: datetime
    updated_at: datetime
    version: str
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class WorkflowExecution:
    """Workflow execution instance"""
    id: str
    template_id: str
    trigger_event: Dict[str, Any]
    user_id: str
    entity_id: Optional[str]
    status: WorkflowStatus
    priority: Priority
    started_at: datetime
    completed_at: Optional[datetime]
    actions: List[WorkflowAction]
    current_action_id: Optional[str]
    execution_context: Dict[str, Any]
    error_message: Optional[str] = None
    metrics: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation"""
        return {
            'id': self.id,
            'template_id': self.template_id,
            'trigger_event': self.trigger_event,
            'user_id': self.user_id,
            'entity_id': self.entity_id,
            'status': self.status.value,
            'priority': self.priority.value,
            'started_at': self.started_at.isoformat(),
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'actions': [action.to_dict() for action in self.actions],
            'current_action_id': self.current_action_id,
            'execution_context': self.execution_context,
            'error_message': self.error_message,
            'metrics': self.metrics
        }

@dataclass
class NotificationChannel:
    """Notification channel configuration"""
    id: str
    type: str  # email, slack, teams, webhook, sms
    name: str
    config: Dict[str, Any]
    enabled: bool
    filters: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ApprovalRequest:
    """Approval request for actions requiring human approval"""
    id: str
    workflow_execution_id: str
    action_id: str
    requester: str
    approver_groups: List[str]
    approval_timeout: datetime
    status: ApprovalStatus
    requested_at: datetime
    approved_at: Optional[datetime]
    approved_by: Optional[str]
    denial_reason: Optional[str]
    context: Dict[str, Any]

class ActionExecutor:
    """Base class for action executors"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        
    async def execute(self, action: WorkflowAction, context: Dict[str, Any]) -> bool:
        """Execute the action"""
        raise NotImplementedError
        
    async def validate(self, action: WorkflowAction) -> bool:
        """Validate action parameters"""
        return True

class UserActionExecutor(ActionExecutor):
    """Executor for user-related actions"""
    
    async def execute(self, action: WorkflowAction, context: Dict[str, Any]) -> bool:
        """Execute user-related actions"""
        try:
            user_id = action.parameters.get('user_id') or context.get('user_id')
            if not user_id:
                raise ValueError("user_id is required")
            
            if action.action_type == ActionType.USER_DISABLE:
                return await self._disable_user(user_id, action.parameters)
            elif action.action_type == ActionType.USER_SUSPEND:
                return await self._suspend_user(user_id, action.parameters)
            elif action.action_type == ActionType.FORCE_PASSWORD_RESET:
                return await self._force_password_reset(user_id, action.parameters)
            elif action.action_type == ActionType.REVOKE_SESSION:
                return await self._revoke_session(user_id, action.parameters)
            elif action.action_type == ActionType.LOCK_ACCOUNT:
                return await self._lock_account(user_id, action.parameters)
            else:
                raise ValueError(f"Unsupported action type: {action.action_type}")
                
        except Exception as e:
            logger.error(f"User action execution failed: {e}")
            action.error_message = str(e)
            return False

    async def _disable_user(self, user_id: str, parameters: Dict[str, Any]) -> bool:
        """Disable user account"""
        try:
            reason = parameters.get('reason', 'Security automation')
            duration = parameters.get('duration_hours')
            
            logger.info(f"Disabling user {user_id} - Reason: {reason}")
            
            # Mock implementation - would integrate with identity provider
            await asyncio.sleep(0.1)  # Simulate API call
            
            # Log the action
            logger.info(f"User {user_id} disabled successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to disable user {user_id}: {e}")
            return False

    async def _suspend_user(self, user_id: str, parameters: Dict[str, Any]) -> bool:
        """Suspend user account temporarily"""
        try:
            reason = parameters.get('reason', 'Security automation')
            duration_hours = parameters.get('duration_hours', 24)
            
            logger.info(f"Suspending user {user_id} for {duration_hours} hours - Reason: {reason}")
            
            # Mock implementation
            await asyncio.sleep(0.1)
            
            logger.info(f"User {user_id} suspended successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to suspend user {user_id}: {e}")
            return False

    async def _force_password_reset(self, user_id: str, parameters: Dict[str, Any]) -> bool:
        """Force password reset for user"""
        try:
            notify_user = parameters.get('notify_user', True)
            
            logger.info(f"Forcing password reset for user {user_id}")
            
            # Mock implementation
            await asyncio.sleep(0.1)
            
            if notify_user:
                # Send notification to user
                logger.info(f"Password reset notification sent to user {user_id}")
            
            logger.info(f"Password reset forced for user {user_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to force password reset for user {user_id}: {e}")
            return False

    async def _revoke_session(self, user_id: str, parameters: Dict[str, Any]) -> bool:
        """Revoke user sessions"""
        try:
            session_ids = parameters.get('session_ids', [])
            revoke_all = parameters.get('revoke_all', False)
            
            if revoke_all:
                logger.info(f"Revoking all sessions for user {user_id}")
            else:
                logger.info(f"Revoking specific sessions for user {user_id}: {session_ids}")
            
            # Mock implementation
            await asyncio.sleep(0.1)
            
            logger.info(f"Sessions revoked for user {user_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to revoke sessions for user {user_id}: {e}")
            return False

    async def _lock_account(self, user_id: str, parameters: Dict[str, Any]) -> bool:
        """Lock user account"""
        try:
            reason = parameters.get('reason', 'Security automation')
            
            logger.info(f"Locking account for user {user_id} - Reason: {reason}")
            
            # Mock implementation
            await asyncio.sleep(0.1)
            
            logger.info(f"Account locked for user {user_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to lock account for user {user_id}: {e}")
            return False

class NetworkActionExecutor(ActionExecutor):
    """Executor for network-related actions"""
    
    async def execute(self, action: WorkflowAction, context: Dict[str, Any]) -> bool:
        """Execute network-related actions"""
        try:
            if action.action_type == ActionType.QUARANTINE_DEVICE:
                return await self._quarantine_device(action.parameters, context)
            elif action.action_type == ActionType.ISOLATE_NETWORK:
                return await self._isolate_network(action.parameters, context)
            elif action.action_type == ActionType.BLOCK_IP:
                return await self._block_ip(action.parameters, context)
            else:
                raise ValueError(f"Unsupported action type: {action.action_type}")
                
        except Exception as e:
            logger.error(f"Network action execution failed: {e}")
            action.error_message = str(e)
            return False

    async def _quarantine_device(self, parameters: Dict[str, Any], context: Dict[str, Any]) -> bool:
        """Quarantine a device"""
        try:
            device_id = parameters.get('device_id') or context.get('device_id')
            quarantine_vlan = parameters.get('quarantine_vlan', 'quarantine')
            
            if not device_id:
                raise ValueError("device_id is required")
            
            logger.info(f"Quarantining device {device_id} to VLAN {quarantine_vlan}")
            
            # Mock implementation - would integrate with network infrastructure
            await asyncio.sleep(0.2)
            
            logger.info(f"Device {device_id} quarantined successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to quarantine device: {e}")
            return False

    async def _isolate_network(self, parameters: Dict[str, Any], context: Dict[str, Any]) -> bool:
        """Isolate network segment"""
        try:
            network_segment = parameters.get('network_segment')
            isolation_duration = parameters.get('duration_minutes', 60)
            
            if not network_segment:
                raise ValueError("network_segment is required")
            
            logger.info(f"Isolating network segment {network_segment} for {isolation_duration} minutes")
            
            # Mock implementation
            await asyncio.sleep(0.2)
            
            logger.info(f"Network segment {network_segment} isolated successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to isolate network: {e}")
            return False

    async def _block_ip(self, parameters: Dict[str, Any], context: Dict[str, Any]) -> bool:
        """Block IP address"""
        try:
            ip_address = parameters.get('ip_address') or context.get('ip_address')
            block_duration = parameters.get('duration_hours', 24)
            
            if not ip_address:
                raise ValueError("ip_address is required")
            
            logger.info(f"Blocking IP {ip_address} for {block_duration} hours")
            
            # Mock implementation - would integrate with firewall/IPS
            await asyncio.sleep(0.1)
            
            logger.info(f"IP {ip_address} blocked successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to block IP: {e}")
            return False

class NotificationExecutor(ActionExecutor):
    """Executor for notification actions"""
    
    def __init__(self, config: Dict[str, Any], channels: Dict[str, NotificationChannel]):
        super().__init__(config)
        self.channels = channels
        
    async def execute(self, action: WorkflowAction, context: Dict[str, Any]) -> bool:
        """Execute notification actions"""
        try:
            if action.action_type == ActionType.EMAIL_ALERT:
                return await self._send_email(action.parameters, context)
            elif action.action_type == ActionType.SLACK_NOTIFICATION:
                return await self._send_slack(action.parameters, context)
            elif action.action_type == ActionType.TEAMS_NOTIFICATION:
                return await self._send_teams(action.parameters, context)
            elif action.action_type == ActionType.TICKET_CREATION:
                return await self._create_ticket(action.parameters, context)
            else:
                raise ValueError(f"Unsupported action type: {action.action_type}")
                
        except Exception as e:
            logger.error(f"Notification action execution failed: {e}")
            action.error_message = str(e)
            return False

    async def _send_email(self, parameters: Dict[str, Any], context: Dict[str, Any]) -> bool:
        """Send email notification"""
        try:
            recipients = parameters.get('recipients', [])
            subject = parameters.get('subject', 'Security Alert')
            template = parameters.get('template', 'default')
            
            # Render template with context
            rendered_subject = self._render_template(subject, context)
            rendered_body = self._render_email_template(template, context)
            
            logger.info(f"Sending email alert to {recipients}")
            logger.info(f"Subject: {rendered_subject}")
            
            # Mock implementation - would integrate with email service
            await asyncio.sleep(0.1)
            
            logger.info("Email sent successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send email: {e}")
            return False

    async def _send_slack(self, parameters: Dict[str, Any], context: Dict[str, Any]) -> bool:
        """Send Slack notification"""
        try:
            channel = parameters.get('channel', '#security-alerts')
            message_template = parameters.get('message', 'Security alert: {{event_type}}')
            
            # Render message with context
            rendered_message = self._render_template(message_template, context)
            
            logger.info(f"Sending Slack notification to {channel}")
            logger.info(f"Message: {rendered_message}")
            
            # Mock implementation - would use Slack API
            await asyncio.sleep(0.1)
            
            logger.info("Slack notification sent successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send Slack notification: {e}")
            return False

    async def _send_teams(self, parameters: Dict[str, Any], context: Dict[str, Any]) -> bool:
        """Send Microsoft Teams notification"""
        try:
            webhook_url = parameters.get('webhook_url')
            message_template = parameters.get('message', 'Security alert: {{event_type}}')
            
            if not webhook_url:
                raise ValueError("webhook_url is required for Teams notifications")
            
            # Render message with context
            rendered_message = self._render_template(message_template, context)
            
            logger.info(f"Sending Teams notification")
            logger.info(f"Message: {rendered_message}")
            
            # Mock implementation - would use Teams webhook
            await asyncio.sleep(0.1)
            
            logger.info("Teams notification sent successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send Teams notification: {e}")
            return False

    async def _create_ticket(self, parameters: Dict[str, Any], context: Dict[str, Any]) -> bool:
        """Create support/incident ticket"""
        try:
            title_template = parameters.get('title', 'Security Incident: {{event_type}}')
            description_template = parameters.get('description', 'Automated security incident')
            priority = parameters.get('priority', 'high')
            assignee = parameters.get('assignee')
            
            # Render templates with context
            rendered_title = self._render_template(title_template, context)
            rendered_description = self._render_template(description_template, context)
            
            logger.info(f"Creating ticket: {rendered_title}")
            logger.info(f"Priority: {priority}, Assignee: {assignee}")
            
            # Mock implementation - would integrate with ticketing system
            await asyncio.sleep(0.2)
            
            ticket_id = f"INC-{int(time.time())}"
            logger.info(f"Ticket created successfully: {ticket_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to create ticket: {e}")
            return False

    def _render_template(self, template: str, context: Dict[str, Any]) -> str:
        """Render Jinja2 template with context"""
        try:
            jinja_template = jinja2.Template(template)
            return jinja_template.render(**context)
        except Exception as e:
            logger.error(f"Template rendering failed: {e}")
            return template

    def _render_email_template(self, template_name: str, context: Dict[str, Any]) -> str:
        """Render email template"""
        try:
            # Mock email template
            templates = {
                'default': '''
Security Alert - {{event_type|default('Unknown Event')}}

User: {{user_id|default('Unknown')}}
Time: {{timestamp|default('Unknown')}}
Risk Score: {{risk_score|default('N/A')}}

Details:
{{event_details|default('No details available')}}

This is an automated message from the iSecTech Identity and Access Analytics system.
''',
                'high_risk': '''
HIGH RISK SECURITY ALERT - {{event_type|default('Unknown Event')}}

IMMEDIATE ATTENTION REQUIRED

User: {{user_id|default('Unknown')}}
Risk Score: {{risk_score|default('N/A')}}
Location: {{location|default('Unknown')}}
Device: {{device|default('Unknown')}}

Automated Actions Taken:
{{actions_taken|default('None')}}

Please investigate immediately.
'''
            }
            
            template_content = templates.get(template_name, templates['default'])
            return self._render_template(template_content, context)
            
        except Exception as e:
            logger.error(f"Email template rendering failed: {e}")
            return "Template rendering error"

class WorkflowEngine:
    """Main workflow orchestration engine"""
    
    def __init__(self, db_path: str = ":memory:", redis_client: Optional[aioredis.Redis] = None):
        self.db_path = db_path
        self.redis_client = redis_client
        self.templates: Dict[str, WorkflowTemplate] = {}
        self.active_executions: Dict[str, WorkflowExecution] = {}
        self.executors: Dict[ActionType, ActionExecutor] = {}
        self.notification_channels: Dict[str, NotificationChannel] = {}
        self.approval_requests: Dict[str, ApprovalRequest] = {}
        self._initialize_database()
        self._initialize_executors()
        self._execution_lock = threading.Lock()
        self._running = False
        
    def _initialize_database(self):
        """Initialize SQLite database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Workflow templates table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS workflow_templates (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT,
                    trigger_type TEXT NOT NULL,
                    trigger_conditions_json TEXT,
                    actions_json TEXT NOT NULL,
                    priority INTEGER NOT NULL,
                    enabled BOOLEAN NOT NULL,
                    created_by TEXT NOT NULL,
                    created_at TIMESTAMP NOT NULL,
                    updated_at TIMESTAMP NOT NULL,
                    version TEXT NOT NULL,
                    tags_json TEXT,
                    metadata_json TEXT
                )
            ''')
            
            # Workflow executions table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS workflow_executions (
                    id TEXT PRIMARY KEY,
                    template_id TEXT NOT NULL,
                    trigger_event_json TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    entity_id TEXT,
                    status TEXT NOT NULL,
                    priority INTEGER NOT NULL,
                    started_at TIMESTAMP NOT NULL,
                    completed_at TIMESTAMP,
                    actions_json TEXT NOT NULL,
                    current_action_id TEXT,
                    execution_context_json TEXT,
                    error_message TEXT,
                    metrics_json TEXT
                )
            ''')
            
            # Approval requests table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS approval_requests (
                    id TEXT PRIMARY KEY,
                    workflow_execution_id TEXT NOT NULL,
                    action_id TEXT NOT NULL,
                    requester TEXT NOT NULL,
                    approver_groups_json TEXT NOT NULL,
                    approval_timeout TIMESTAMP NOT NULL,
                    status TEXT NOT NULL,
                    requested_at TIMESTAMP NOT NULL,
                    approved_at TIMESTAMP,
                    approved_by TEXT,
                    denial_reason TEXT,
                    context_json TEXT
                )
            ''')
            
            # Notification channels table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS notification_channels (
                    id TEXT PRIMARY KEY,
                    type TEXT NOT NULL,
                    name TEXT NOT NULL,
                    config_json TEXT NOT NULL,
                    enabled BOOLEAN NOT NULL,
                    filters_json TEXT
                )
            ''')
            
            # Create indexes
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_workflow_executions_status ON workflow_executions(status)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_workflow_executions_user_id ON workflow_executions(user_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_workflow_executions_started_at ON workflow_executions(started_at)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_approval_requests_status ON approval_requests(status)')
            
            conn.commit()
            conn.close()
            
            logger.info("Workflow database initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize database: {e}")
            raise

    def _initialize_executors(self):
        """Initialize action executors"""
        try:
            # User action executor
            user_executor = UserActionExecutor({})
            for action_type in [ActionType.USER_DISABLE, ActionType.USER_SUSPEND, 
                              ActionType.FORCE_PASSWORD_RESET, ActionType.REVOKE_SESSION,
                              ActionType.LOCK_ACCOUNT]:
                self.executors[action_type] = user_executor
            
            # Network action executor
            network_executor = NetworkActionExecutor({})
            for action_type in [ActionType.QUARANTINE_DEVICE, ActionType.ISOLATE_NETWORK,
                              ActionType.BLOCK_IP]:
                self.executors[action_type] = network_executor
            
            # Notification executor
            notification_executor = NotificationExecutor({}, self.notification_channels)
            for action_type in [ActionType.EMAIL_ALERT, ActionType.SLACK_NOTIFICATION,
                              ActionType.TEAMS_NOTIFICATION, ActionType.TICKET_CREATION]:
                self.executors[action_type] = notification_executor
            
            logger.info("Action executors initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize executors: {e}")
            raise

    async def register_template(self, template: WorkflowTemplate) -> bool:
        """Register a workflow template"""
        try:
            # Validate template
            if not self._validate_template(template):
                return False
            
            # Store in database
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO workflow_templates (
                    id, name, description, trigger_type, trigger_conditions_json,
                    actions_json, priority, enabled, created_by, created_at,
                    updated_at, version, tags_json, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                template.id,
                template.name,
                template.description,
                template.trigger_type.value,
                json.dumps(template.trigger_conditions),
                json.dumps([action.to_dict() for action in template.actions]),
                template.priority.value,
                template.enabled,
                template.created_by,
                template.created_at.isoformat(),
                template.updated_at.isoformat(),
                template.version,
                json.dumps(template.tags),
                json.dumps(template.metadata)
            ))
            
            conn.commit()
            conn.close()
            
            # Store in memory
            self.templates[template.id] = template
            
            logger.info(f"Workflow template registered: {template.id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to register template: {e}")
            return False

    def _validate_template(self, template: WorkflowTemplate) -> bool:
        """Validate workflow template"""
        try:
            # Check required fields
            if not template.id or not template.name or not template.actions:
                logger.error("Template missing required fields")
                return False
            
            # Validate actions
            action_ids = set()
            for action in template.actions:
                if not action.id or action.id in action_ids:
                    logger.error(f"Invalid or duplicate action ID: {action.id}")
                    return False
                action_ids.add(action.id)
                
                # Check if executor exists for action type
                if action.action_type not in self.executors:
                    logger.error(f"No executor found for action type: {action.action_type}")
                    return False
            
            # Validate action references
            for action in template.actions:
                if action.on_success:
                    for ref_id in action.on_success:
                        if ref_id not in action_ids:
                            logger.error(f"Invalid action reference in on_success: {ref_id}")
                            return False
                
                if action.on_failure:
                    for ref_id in action.on_failure:
                        if ref_id not in action_ids:
                            logger.error(f"Invalid action reference in on_failure: {ref_id}")
                            return False
            
            return True
            
        except Exception as e:
            logger.error(f"Template validation failed: {e}")
            return False

    async def trigger_workflow(self, trigger_type: TriggerType, event_data: Dict[str, Any],
                             user_id: str, entity_id: Optional[str] = None) -> List[str]:
        """Trigger workflows based on event"""
        try:
            triggered_executions = []
            
            # Find matching templates
            matching_templates = await self._find_matching_templates(trigger_type, event_data)
            
            for template in matching_templates:
                # Create workflow execution
                execution_id = str(uuid.uuid4())
                execution = WorkflowExecution(
                    id=execution_id,
                    template_id=template.id,
                    trigger_event=event_data,
                    user_id=user_id,
                    entity_id=entity_id,
                    status=WorkflowStatus.PENDING,
                    priority=template.priority,
                    started_at=datetime.utcnow(),
                    completed_at=None,
                    actions=[self._clone_action(action) for action in template.actions],
                    current_action_id=None,
                    execution_context=event_data.copy(),
                    metrics={'actions_executed': 0, 'actions_failed': 0}
                )
                
                # Store execution
                await self._store_execution(execution)
                
                # Add to active executions
                with self._execution_lock:
                    self.active_executions[execution_id] = execution
                
                # Start execution asynchronously
                asyncio.create_task(self._execute_workflow(execution))
                
                triggered_executions.append(execution_id)
                
            logger.info(f"Triggered {len(triggered_executions)} workflows for event: {trigger_type.value}")
            return triggered_executions
            
        except Exception as e:
            logger.error(f"Failed to trigger workflows: {e}")
            return []

    async def _find_matching_templates(self, trigger_type: TriggerType, 
                                     event_data: Dict[str, Any]) -> List[WorkflowTemplate]:
        """Find workflow templates matching the trigger"""
        matching_templates = []
        
        try:
            for template in self.templates.values():
                if not template.enabled:
                    continue
                    
                if template.trigger_type != trigger_type:
                    continue
                
                # Check trigger conditions
                if await self._evaluate_trigger_conditions(template, event_data):
                    matching_templates.append(template)
            
            # Sort by priority (higher priority first)
            matching_templates.sort(key=lambda t: t.priority.value, reverse=True)
            
            return matching_templates
            
        except Exception as e:
            logger.error(f"Failed to find matching templates: {e}")
            return []

    async def _evaluate_trigger_conditions(self, template: WorkflowTemplate,
                                         event_data: Dict[str, Any]) -> bool:
        """Evaluate trigger conditions"""
        try:
            conditions = template.trigger_conditions
            if not conditions:
                return True  # No conditions means always match
            
            # Simple condition evaluation
            for key, expected_value in conditions.items():
                if key not in event_data:
                    return False
                
                actual_value = event_data[key]
                
                # Handle different comparison types
                if isinstance(expected_value, dict):
                    operator = expected_value.get('operator', 'eq')
                    value = expected_value.get('value')
                    
                    if operator == 'eq' and actual_value != value:
                        return False
                    elif operator == 'gt' and actual_value <= value:
                        return False
                    elif operator == 'lt' and actual_value >= value:
                        return False
                    elif operator == 'gte' and actual_value < value:
                        return False
                    elif operator == 'lte' and actual_value > value:
                        return False
                    elif operator == 'contains' and value not in str(actual_value):
                        return False
                    elif operator == 'in' and actual_value not in value:
                        return False
                else:
                    if actual_value != expected_value:
                        return False
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to evaluate trigger conditions: {e}")
            return False

    def _clone_action(self, action: WorkflowAction) -> WorkflowAction:
        """Clone workflow action for execution"""
        return WorkflowAction(
            id=action.id,
            action_type=action.action_type,
            parameters=action.parameters.copy(),
            timeout_seconds=action.timeout_seconds,
            retry_count=0,
            max_retries=action.max_retries,
            requires_approval=action.requires_approval,
            approval_timeout=action.approval_timeout,
            condition=action.condition,
            on_success=action.on_success.copy() if action.on_success else None,
            on_failure=action.on_failure.copy() if action.on_failure else None
        )

    async def _execute_workflow(self, execution: WorkflowExecution):
        """Execute workflow instance"""
        try:
            logger.info(f"Starting workflow execution: {execution.id}")
            
            execution.status = WorkflowStatus.RUNNING
            await self._update_execution_status(execution)
            
            # Find entry point actions (actions with no dependencies)
            entry_actions = self._find_entry_actions(execution.actions)
            
            if not entry_actions:
                execution.status = WorkflowStatus.FAILED
                execution.error_message = "No entry point actions found"
                await self._update_execution_status(execution)
                return
            
            # Execute actions
            await self._execute_actions(execution, entry_actions)
            
            # Complete workflow
            if execution.status == WorkflowStatus.RUNNING:
                execution.status = WorkflowStatus.COMPLETED
                execution.completed_at = datetime.utcnow()
                await self._update_execution_status(execution)
            
            logger.info(f"Workflow execution completed: {execution.id} ({execution.status.value})")
            
        except Exception as e:
            logger.error(f"Workflow execution failed: {e}")
            execution.status = WorkflowStatus.FAILED
            execution.error_message = str(e)
            execution.completed_at = datetime.utcnow()
            await self._update_execution_status(execution)
        finally:
            # Remove from active executions
            with self._execution_lock:
                if execution.id in self.active_executions:
                    del self.active_executions[execution.id]

    def _find_entry_actions(self, actions: List[WorkflowAction]) -> List[WorkflowAction]:
        """Find actions that don't depend on others (entry points)"""
        referenced_actions = set()
        
        # Collect all referenced action IDs
        for action in actions:
            if action.on_success:
                referenced_actions.update(action.on_success)
            if action.on_failure:
                referenced_actions.update(action.on_failure)
        
        # Entry actions are those not referenced by others
        entry_actions = [action for action in actions if action.id not in referenced_actions]
        
        return entry_actions

    async def _execute_actions(self, execution: WorkflowExecution, actions: List[WorkflowAction]):
        """Execute a set of actions"""
        try:
            # Execute actions in parallel
            tasks = []
            for action in actions:
                task = asyncio.create_task(self._execute_single_action(execution, action))
                tasks.append(task)
            
            # Wait for all actions to complete
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Process results and determine next actions
            next_actions = []
            for i, result in enumerate(results):
                action = actions[i]
                
                if isinstance(result, Exception):
                    logger.error(f"Action {action.id} failed with exception: {result}")
                    action.status = WorkflowStatus.FAILED
                    action.error_message = str(result)
                    execution.metrics['actions_failed'] += 1
                    
                    # Add failure actions to next set
                    if action.on_failure:
                        next_actions.extend(self._get_actions_by_ids(execution.actions, action.on_failure))
                else:
                    success = result
                    if success:
                        action.status = WorkflowStatus.COMPLETED
                        execution.metrics['actions_executed'] += 1
                        
                        # Add success actions to next set
                        if action.on_success:
                            next_actions.extend(self._get_actions_by_ids(execution.actions, action.on_success))
                    else:
                        action.status = WorkflowStatus.FAILED
                        execution.metrics['actions_failed'] += 1
                        
                        # Add failure actions to next set
                        if action.on_failure:
                            next_actions.extend(self._get_actions_by_ids(execution.actions, action.on_failure))
            
            # Execute next actions if any
            if next_actions:
                await self._execute_actions(execution, next_actions)
                
        except Exception as e:
            logger.error(f"Failed to execute actions: {e}")
            raise

    def _get_actions_by_ids(self, actions: List[WorkflowAction], action_ids: List[str]) -> List[WorkflowAction]:
        """Get actions by their IDs"""
        id_to_action = {action.id: action for action in actions}
        return [id_to_action[action_id] for action_id in action_ids if action_id in id_to_action]

    async def _execute_single_action(self, execution: WorkflowExecution, action: WorkflowAction) -> bool:
        """Execute a single action"""
        try:
            logger.info(f"Executing action: {action.id} ({action.action_type.value})")
            
            action.status = WorkflowStatus.RUNNING
            action.started_at = datetime.utcnow()
            
            # Check condition if specified
            if action.condition:
                if not self._evaluate_condition(action.condition, execution.execution_context):
                    logger.info(f"Action condition not met, skipping: {action.id}")
                    action.status = WorkflowStatus.COMPLETED
                    action.completed_at = datetime.utcnow()
                    return True
            
            # Check if approval is required
            if action.requires_approval:
                approval_result = await self._request_approval(execution, action)
                if not approval_result:
                    logger.info(f"Action approval denied or timed out: {action.id}")
                    action.status = WorkflowStatus.FAILED
                    action.error_message = "Approval denied or timed out"
                    action.completed_at = datetime.utcnow()
                    return False
            
            # Execute with retry logic
            success = False
            for attempt in range(action.max_retries + 1):
                try:
                    # Get executor
                    executor = self.executors.get(action.action_type)
                    if not executor:
                        raise ValueError(f"No executor found for action type: {action.action_type}")
                    
                    # Execute with timeout
                    success = await asyncio.wait_for(
                        executor.execute(action, execution.execution_context),
                        timeout=action.timeout_seconds
                    )
                    
                    if success:
                        break
                    else:
                        action.retry_count = attempt + 1
                        if attempt < action.max_retries:
                            await asyncio.sleep(2 ** attempt)  # Exponential backoff
                        
                except asyncio.TimeoutError:
                    action.error_message = f"Action timed out after {action.timeout_seconds} seconds"
                    action.retry_count = attempt + 1
                    if attempt < action.max_retries:
                        await asyncio.sleep(2 ** attempt)
                except Exception as e:
                    action.error_message = str(e)
                    action.retry_count = attempt + 1
                    if attempt < action.max_retries:
                        await asyncio.sleep(2 ** attempt)
            
            action.completed_at = datetime.utcnow()
            
            if success:
                action.status = WorkflowStatus.COMPLETED
                logger.info(f"Action completed successfully: {action.id}")
            else:
                action.status = WorkflowStatus.FAILED
                logger.error(f"Action failed after {action.max_retries + 1} attempts: {action.id}")
            
            return success
            
        except Exception as e:
            logger.error(f"Failed to execute action {action.id}: {e}")
            action.status = WorkflowStatus.FAILED
            action.error_message = str(e)
            action.completed_at = datetime.utcnow()
            return False

    def _evaluate_condition(self, condition: str, context: Dict[str, Any]) -> bool:
        """Evaluate action condition"""
        try:
            # Simple condition evaluation using eval (in production, use a safer approach)
            # This is a simplified implementation for demonstration
            return True  # Always return True for now
            
        except Exception as e:
            logger.error(f"Failed to evaluate condition: {e}")
            return False

    async def _request_approval(self, execution: WorkflowExecution, action: WorkflowAction) -> bool:
        """Request approval for action"""
        try:
            approval_request = ApprovalRequest(
                id=str(uuid.uuid4()),
                workflow_execution_id=execution.id,
                action_id=action.id,
                requester='system',
                approver_groups=['security_team', 'it_admins'],
                approval_timeout=datetime.utcnow() + timedelta(minutes=action.approval_timeout or 30),
                status=ApprovalStatus.PENDING,
                requested_at=datetime.utcnow(),
                approved_at=None,
                approved_by=None,
                denial_reason=None,
                context={
                    'action_type': action.action_type.value,
                    'parameters': action.parameters,
                    'user_id': execution.user_id,
                    'trigger_event': execution.trigger_event
                }
            )
            
            # Store approval request
            await self._store_approval_request(approval_request)
            self.approval_requests[approval_request.id] = approval_request
            
            # Send approval notification
            await self._send_approval_notification(approval_request)
            
            # Wait for approval (simplified - in production, this would be event-driven)
            timeout_seconds = action.approval_timeout or 1800  # 30 minutes default
            start_time = time.time()
            
            while time.time() - start_time < timeout_seconds:
                # Check approval status
                approval_request = self.approval_requests.get(approval_request.id)
                if approval_request and approval_request.status == ApprovalStatus.APPROVED:
                    action.approval_status = ApprovalStatus.APPROVED
                    action.approved_by = approval_request.approved_by
                    return True
                elif approval_request and approval_request.status == ApprovalStatus.DENIED:
                    action.approval_status = ApprovalStatus.DENIED
                    return False
                
                await asyncio.sleep(10)  # Check every 10 seconds
            
            # Timeout
            approval_request.status = ApprovalStatus.EXPIRED
            action.approval_status = ApprovalStatus.EXPIRED
            return False
            
        except Exception as e:
            logger.error(f"Failed to request approval: {e}")
            return False

    async def _send_approval_notification(self, approval_request: ApprovalRequest):
        """Send approval notification"""
        try:
            # Mock implementation - would send to approval system/channels
            logger.info(f"Approval notification sent for request: {approval_request.id}")
            
        except Exception as e:
            logger.error(f"Failed to send approval notification: {e}")

    async def approve_action(self, approval_request_id: str, approver: str) -> bool:
        """Approve a pending action"""
        try:
            approval_request = self.approval_requests.get(approval_request_id)
            if not approval_request:
                logger.error(f"Approval request not found: {approval_request_id}")
                return False
            
            if approval_request.status != ApprovalStatus.PENDING:
                logger.error(f"Approval request not in pending status: {approval_request_id}")
                return False
            
            if datetime.utcnow() > approval_request.approval_timeout:
                approval_request.status = ApprovalStatus.EXPIRED
                logger.error(f"Approval request expired: {approval_request_id}")
                return False
            
            approval_request.status = ApprovalStatus.APPROVED
            approval_request.approved_at = datetime.utcnow()
            approval_request.approved_by = approver
            
            await self._update_approval_request(approval_request)
            
            logger.info(f"Action approved: {approval_request_id} by {approver}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to approve action: {e}")
            return False

    async def deny_action(self, approval_request_id: str, approver: str, reason: str) -> bool:
        """Deny a pending action"""
        try:
            approval_request = self.approval_requests.get(approval_request_id)
            if not approval_request:
                logger.error(f"Approval request not found: {approval_request_id}")
                return False
            
            if approval_request.status != ApprovalStatus.PENDING:
                logger.error(f"Approval request not in pending status: {approval_request_id}")
                return False
            
            approval_request.status = ApprovalStatus.DENIED
            approval_request.approved_at = datetime.utcnow()
            approval_request.approved_by = approver
            approval_request.denial_reason = reason
            
            await self._update_approval_request(approval_request)
            
            logger.info(f"Action denied: {approval_request_id} by {approver} - Reason: {reason}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to deny action: {e}")
            return False

    async def _store_execution(self, execution: WorkflowExecution):
        """Store workflow execution in database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO workflow_executions (
                    id, template_id, trigger_event_json, user_id, entity_id,
                    status, priority, started_at, completed_at, actions_json,
                    current_action_id, execution_context_json, error_message, metrics_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                execution.id,
                execution.template_id,
                json.dumps(execution.trigger_event),
                execution.user_id,
                execution.entity_id,
                execution.status.value,
                execution.priority.value,
                execution.started_at.isoformat(),
                execution.completed_at.isoformat() if execution.completed_at else None,
                json.dumps([action.to_dict() for action in execution.actions]),
                execution.current_action_id,
                json.dumps(execution.execution_context),
                execution.error_message,
                json.dumps(execution.metrics)
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Failed to store execution: {e}")

    async def _update_execution_status(self, execution: WorkflowExecution):
        """Update execution status in database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                UPDATE workflow_executions 
                SET status = ?, completed_at = ?, error_message = ?, 
                    actions_json = ?, metrics_json = ?
                WHERE id = ?
            ''', (
                execution.status.value,
                execution.completed_at.isoformat() if execution.completed_at else None,
                execution.error_message,
                json.dumps([action.to_dict() for action in execution.actions]),
                json.dumps(execution.metrics),
                execution.id
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Failed to update execution status: {e}")

    async def _store_approval_request(self, approval_request: ApprovalRequest):
        """Store approval request in database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO approval_requests (
                    id, workflow_execution_id, action_id, requester,
                    approver_groups_json, approval_timeout, status,
                    requested_at, approved_at, approved_by, denial_reason, context_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                approval_request.id,
                approval_request.workflow_execution_id,
                approval_request.action_id,
                approval_request.requester,
                json.dumps(approval_request.approver_groups),
                approval_request.approval_timeout.isoformat(),
                approval_request.status.value,
                approval_request.requested_at.isoformat(),
                approval_request.approved_at.isoformat() if approval_request.approved_at else None,
                approval_request.approved_by,
                approval_request.denial_reason,
                json.dumps(approval_request.context)
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Failed to store approval request: {e}")

    async def _update_approval_request(self, approval_request: ApprovalRequest):
        """Update approval request in database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                UPDATE approval_requests 
                SET status = ?, approved_at = ?, approved_by = ?, denial_reason = ?
                WHERE id = ?
            ''', (
                approval_request.status.value,
                approval_request.approved_at.isoformat() if approval_request.approved_at else None,
                approval_request.approved_by,
                approval_request.denial_reason,
                approval_request.id
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Failed to update approval request: {e}")

    async def get_workflow_status(self, execution_id: str) -> Optional[Dict[str, Any]]:
        """Get workflow execution status"""
        try:
            # Check active executions first
            if execution_id in self.active_executions:
                execution = self.active_executions[execution_id]
                return execution.to_dict()
            
            # Check database
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT * FROM workflow_executions WHERE id = ?
            ''', (execution_id,))
            
            row = cursor.fetchone()
            conn.close()
            
            if row:
                return {
                    'id': row[0],
                    'template_id': row[1],
                    'trigger_event': json.loads(row[2]) if row[2] else {},
                    'user_id': row[3],
                    'entity_id': row[4],
                    'status': row[5],
                    'priority': row[6],
                    'started_at': row[7],
                    'completed_at': row[8],
                    'actions': json.loads(row[9]) if row[9] else [],
                    'current_action_id': row[10],
                    'execution_context': json.loads(row[11]) if row[11] else {},
                    'error_message': row[12],
                    'metrics': json.loads(row[13]) if row[13] else {}
                }
            
            return None
            
        except Exception as e:
            logger.error(f"Failed to get workflow status: {e}")
            return None

    async def get_execution_history(self, user_id: Optional[str] = None,
                                  days: int = 30, limit: int = 100) -> List[Dict[str, Any]]:
        """Get workflow execution history"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            start_date = datetime.utcnow() - timedelta(days=days)
            
            if user_id:
                cursor.execute('''
                    SELECT id, template_id, user_id, status, priority, started_at, completed_at
                    FROM workflow_executions
                    WHERE user_id = ? AND started_at >= ?
                    ORDER BY started_at DESC
                    LIMIT ?
                ''', (user_id, start_date.isoformat(), limit))
            else:
                cursor.execute('''
                    SELECT id, template_id, user_id, status, priority, started_at, completed_at
                    FROM workflow_executions
                    WHERE started_at >= ?
                    ORDER BY started_at DESC
                    LIMIT ?
                ''', (start_date.isoformat(), limit))
            
            rows = cursor.fetchall()
            conn.close()
            
            return [
                {
                    'id': row[0],
                    'template_id': row[1],
                    'user_id': row[2],
                    'status': row[3],
                    'priority': row[4],
                    'started_at': row[5],
                    'completed_at': row[6]
                }
                for row in rows
            ]
            
        except Exception as e:
            logger.error(f"Failed to get execution history: {e}")
            return []

# Example usage and testing
if __name__ == "__main__":
    async def test_workflow_automation():
        """Test the workflow automation system"""
        try:
            # Initialize workflow engine
            engine = WorkflowEngine()
            
            # Create a sample workflow template
            high_risk_template = WorkflowTemplate(
                id="high_risk_response",
                name="High Risk User Response",
                description="Automated response for high-risk user activities",
                trigger_type=TriggerType.RISK_SCORE_THRESHOLD,
                trigger_conditions={'risk_score': {'operator': 'gte', 'value': 80}},
                actions=[
                    WorkflowAction(
                        id="notify_security",
                        action_type=ActionType.EMAIL_ALERT,
                        parameters={
                            'recipients': ['security@isectech.com'],
                            'subject': 'High Risk Alert - User {{user_id}}',
                            'template': 'high_risk'
                        },
                        timeout_seconds=30,
                        retry_count=0,
                        max_retries=2,
                        requires_approval=False,
                        approval_timeout=None,
                        condition=None,
                        on_success=['suspend_user'],
                        on_failure=['escalate_to_admin']
                    ),
                    WorkflowAction(
                        id="suspend_user",
                        action_type=ActionType.USER_SUSPEND,
                        parameters={
                            'reason': 'High risk activity detected',
                            'duration_hours': 24
                        },
                        timeout_seconds=60,
                        retry_count=0,
                        max_retries=3,
                        requires_approval=True,
                        approval_timeout=30,
                        condition=None,
                        on_success=['create_ticket'],
                        on_failure=['escalate_to_admin']
                    ),
                    WorkflowAction(
                        id="create_ticket",
                        action_type=ActionType.TICKET_CREATION,
                        parameters={
                            'title': 'High Risk User Activity - {{user_id}}',
                            'description': 'User suspended due to high risk score: {{risk_score}}',
                            'priority': 'high',
                            'assignee': 'security_team'
                        },
                        timeout_seconds=45,
                        retry_count=0,
                        max_retries=2,
                        requires_approval=False,
                        approval_timeout=None,
                        condition=None,
                        on_success=None,
                        on_failure=None
                    ),
                    WorkflowAction(
                        id="escalate_to_admin",
                        action_type=ActionType.SECURITY_TEAM_ESCALATION,
                        parameters={
                            'escalation_level': 'critical',
                            'notify_ciso': True
                        },
                        timeout_seconds=30,
                        retry_count=0,
                        max_retries=1,
                        requires_approval=False,
                        approval_timeout=None,
                        condition=None,
                        on_success=None,
                        on_failure=None
                    )
                ],
                priority=Priority.HIGH,
                enabled=True,
                created_by='system',
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow(),
                version='1.0',
                tags=['security', 'automated_response', 'high_risk']
            )
            
            # Register the template
            success = await engine.register_template(high_risk_template)
            print(f"Template registration: {'Success' if success else 'Failed'}")
            
            # Simulate a high-risk event
            high_risk_event = {
                'event_type': 'high_risk_detected',
                'risk_score': 85.5,
                'user_id': 'john.doe@isectech.com',
                'ip_address': '198.51.100.1',
                'location': {'country': 'CN', 'city': 'Beijing'},
                'device': {'device_id': 'unknown_device_123', 'type': 'mobile'},
                'timestamp': datetime.utcnow().isoformat(),
                'details': 'User accessed sensitive data from suspicious location'
            }
            
            # Trigger workflow
            execution_ids = await engine.trigger_workflow(
                TriggerType.RISK_SCORE_THRESHOLD,
                high_risk_event,
                'john.doe@isectech.com'
            )
            
            print(f"Triggered workflows: {execution_ids}")
            
            if execution_ids:
                execution_id = execution_ids[0]
                
                # Wait a bit for workflow to start
                await asyncio.sleep(2)
                
                # Check workflow status
                status = await engine.get_workflow_status(execution_id)
                if status:
                    print(f"Workflow status: {status['status']}")
                    print(f"Actions executed: {status['metrics'].get('actions_executed', 0)}")
                    print(f"Actions failed: {status['metrics'].get('actions_failed', 0)}")
                
                # Simulate approval for user suspension
                pending_approvals = [req for req in engine.approval_requests.values() 
                                   if req.status == ApprovalStatus.PENDING]
                
                if pending_approvals:
                    approval_req = pending_approvals[0]
                    print(f"Approving action: {approval_req.action_id}")
                    await engine.approve_action(approval_req.id, 'security_admin')
                
                # Wait for workflow completion
                await asyncio.sleep(5)
                
                # Final status check
                final_status = await engine.get_workflow_status(execution_id)
                if final_status:
                    print(f"Final workflow status: {final_status['status']}")
                    print(f"Completed at: {final_status['completed_at']}")
            
            # Test execution history
            history = await engine.get_execution_history(days=1, limit=10)
            print(f"Execution history: {len(history)} records")
            
            for record in history:
                print(f"  - {record['id']}: {record['status']} ({record['started_at']})")
            
        except Exception as e:
            logger.error(f"Test failed: {e}")
            logger.error(traceback.format_exc())
    
    # Run the test
    asyncio.run(test_workflow_automation())