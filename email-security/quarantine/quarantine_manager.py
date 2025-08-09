"""
Quarantine and User Management System for ISECTECH Email Security Integration

This module provides comprehensive quarantine management including:
- Centralized quarantine storage and management
- User-facing quarantine interface and self-service
- Administrative quarantine management tools
- Automated notification and alert systems
- Release/approval workflows with audit trails
- Production-grade security and compliance

Author: ISECTECH Security Team
Version: 1.0.0
"""

import asyncio
import json
import logging
import sqlite3
import uuid
import hashlib
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Set, Union
from dataclasses import dataclass, asdict
from enum import Enum
import aiohttp
from email.message import EmailMessage
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Configure logging  
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class QuarantineReason(Enum):
    """Reasons for email quarantine"""
    PHISHING_DETECTED = "phishing_detected"
    MALWARE_DETECTED = "malware_detected"
    SPAM_DETECTED = "spam_detected"
    POLICY_VIOLATION = "policy_violation"
    SUSPICIOUS_CONTENT = "suspicious_content"
    ATTACHMENT_BLOCKED = "attachment_blocked"
    URL_BLOCKED = "url_blocked"
    SENDER_BLOCKED = "sender_blocked"
    DOMAIN_BLOCKED = "domain_blocked"
    AUTHENTICATION_FAILED = "authentication_failed"
    MANUAL_QUARANTINE = "manual_quarantine"
    BEC_DETECTED = "bec_detected"


class QuarantineStatus(Enum):
    """Quarantine item status"""
    QUARANTINED = "quarantined"
    PENDING_REVIEW = "pending_review"
    APPROVED_RELEASE = "approved_release"
    RELEASED = "released"
    DELETED = "deleted"
    EXPIRED = "expired"
    FALSE_POSITIVE = "false_positive"


class NotificationType(Enum):
    """Types of notifications"""
    QUARANTINE_NOTIFICATION = "quarantine_notification"
    DIGEST_SUMMARY = "digest_summary"
    RELEASE_NOTIFICATION = "release_notification"
    ADMIN_ALERT = "admin_alert"
    POLICY_UPDATE = "policy_update"
    SYSTEM_MAINTENANCE = "system_maintenance"


class UserRole(Enum):
    """User roles for quarantine access"""
    END_USER = "end_user"
    SECURITY_ANALYST = "security_analyst"
    ADMIN = "admin"
    SUPER_ADMIN = "super_admin"
    AUDITOR = "auditor"


@dataclass
class QuarantineItem:
    """Quarantined email item"""
    quarantine_id: str
    original_message_id: str
    recipient_email: str
    sender_email: str
    subject: str
    quarantine_reason: QuarantineReason
    quarantine_timestamp: datetime
    expiry_timestamp: datetime
    status: QuarantineStatus
    risk_score: float
    confidence_score: float
    detection_engines: List[str]
    file_path: Optional[str]
    file_size: int
    admin_notes: str
    release_request_count: int
    last_release_request: Optional[datetime]
    released_by: Optional[str]
    release_timestamp: Optional[datetime]
    tags: List[str]


@dataclass
class ReleaseRequest:
    """Email release request from user"""
    request_id: str
    quarantine_id: str
    requesting_user: str
    request_reason: str
    request_timestamp: datetime
    status: str
    reviewed_by: Optional[str]
    review_timestamp: Optional[datetime]
    review_decision: Optional[str]
    review_notes: Optional[str]


@dataclass
class NotificationPreferences:
    """User notification preferences"""
    user_email: str
    immediate_notifications: bool
    daily_digest: bool
    weekly_digest: bool
    release_notifications: bool
    admin_alerts: bool
    preferred_time: str  # HH:MM format
    timezone: str
    enabled: bool


@dataclass
class UserQuarantineStats:
    """User quarantine statistics"""
    user_email: str
    total_quarantined: int
    quarantined_this_week: int
    quarantined_this_month: int
    total_released: int
    false_positives: int
    most_common_reason: str
    avg_risk_score: float
    last_quarantine: Optional[datetime]


@dataclass
class AdminDashboardStats:
    """Administrative dashboard statistics"""
    total_quarantined: int
    quarantined_today: int
    quarantined_this_week: int
    pending_review: int
    top_reasons: Dict[str, int]
    top_senders: Dict[str, int]
    avg_processing_time: float
    false_positive_rate: float
    storage_usage_mb: float


class QuarantineManager:
    """
    Advanced quarantine and user management system
    
    Provides centralized quarantine management with user interfaces,
    administrative controls, and automated notification systems.
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        """Initialize quarantine manager"""
        self.config = config or self._get_default_config()
        self.data_dir = Path(self.config.get('data_directory', '/tmp/quarantine'))
        self.quarantine_storage = self.data_dir / 'storage'
        self.quarantine_storage.mkdir(parents=True, exist_ok=True)
        
        # Initialize database
        self._init_database()
        
        # User preferences cache
        self.user_preferences: Dict[str, NotificationPreferences] = {}
        
        # HTTP session for API calls
        self.session: Optional[aiohttp.ClientSession] = None
        
        # Performance tracking
        self.quarantine_stats = {
            'total_quarantined': 0,
            'total_released': 0,
            'false_positives': 0,
            'avg_storage_time': 0.0,
            'user_satisfaction': 0.0
        }
        
        logger.info("Quarantine Manager initialized")
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration"""
        return {
            'data_directory': '/tmp/quarantine',
            'default_retention_days': 30,
            'max_quarantine_size_gb': 100,
            'auto_purge_enabled': True,
            'user_self_service_enabled': True,
            'admin_approval_required': True,
            'notification_enabled': True,
            'digest_frequency': 'daily',
            'smtp_server': 'localhost',
            'smtp_port': 587,
            'smtp_username': '',
            'smtp_password': '',
            'from_address': 'quarantine@isectech.com',
            'web_interface_url': 'https://security.isectech.com/quarantine',
            'max_release_requests_per_day': 10,
            'auto_release_false_positives': False
        }
    
    def _init_database(self):
        """Initialize SQLite database for quarantine management"""
        db_path = self.data_dir / 'quarantine.db'
        self.db_connection = sqlite3.connect(str(db_path), check_same_thread=False)
        
        self.db_connection.execute('''
            CREATE TABLE IF NOT EXISTS quarantine_items (
                quarantine_id TEXT PRIMARY KEY,
                original_message_id TEXT,
                recipient_email TEXT,
                sender_email TEXT,
                subject TEXT,
                quarantine_reason TEXT,
                quarantine_timestamp REAL,
                expiry_timestamp REAL,
                status TEXT,
                risk_score REAL,
                confidence_score REAL,
                detection_engines TEXT,
                file_path TEXT,
                file_size INTEGER,
                admin_notes TEXT,
                release_request_count INTEGER DEFAULT 0,
                last_release_request REAL,
                released_by TEXT,
                release_timestamp REAL,
                tags TEXT
            )
        ''')
        
        self.db_connection.execute('''
            CREATE TABLE IF NOT EXISTS release_requests (
                request_id TEXT PRIMARY KEY,
                quarantine_id TEXT,
                requesting_user TEXT,
                request_reason TEXT,
                request_timestamp REAL,
                status TEXT,
                reviewed_by TEXT,
                review_timestamp REAL,
                review_decision TEXT,
                review_notes TEXT,
                FOREIGN KEY (quarantine_id) REFERENCES quarantine_items (quarantine_id)
            )
        ''')
        
        self.db_connection.execute('''
            CREATE TABLE IF NOT EXISTS notification_preferences (
                user_email TEXT PRIMARY KEY,
                immediate_notifications BOOLEAN DEFAULT 1,
                daily_digest BOOLEAN DEFAULT 1,
                weekly_digest BOOLEAN DEFAULT 0,
                release_notifications BOOLEAN DEFAULT 1,
                admin_alerts BOOLEAN DEFAULT 0,
                preferred_time TEXT DEFAULT '09:00',
                timezone TEXT DEFAULT 'UTC',
                enabled BOOLEAN DEFAULT 1
            )
        ''')
        
        self.db_connection.execute('''
            CREATE TABLE IF NOT EXISTS notification_log (
                notification_id TEXT PRIMARY KEY,
                user_email TEXT,
                notification_type TEXT,
                subject TEXT,
                sent_timestamp REAL,
                delivery_status TEXT,
                retry_count INTEGER DEFAULT 0
            )
        ''')
        
        self.db_connection.execute('''
            CREATE TABLE IF NOT EXISTS audit_log (
                audit_id TEXT PRIMARY KEY,
                quarantine_id TEXT,
                user_email TEXT,
                action TEXT,
                details TEXT,
                timestamp REAL,
                ip_address TEXT,
                user_agent TEXT
            )
        ''')
        
        # Create indexes for performance
        self.db_connection.execute('''
            CREATE INDEX IF NOT EXISTS idx_recipient_email ON quarantine_items(recipient_email)
        ''')
        
        self.db_connection.execute('''
            CREATE INDEX IF NOT EXISTS idx_quarantine_timestamp ON quarantine_items(quarantine_timestamp)
        ''')
        
        self.db_connection.execute('''
            CREATE INDEX IF NOT EXISTS idx_status ON quarantine_items(status)
        ''')
        
        self.db_connection.commit()
    
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
    
    async def quarantine_email(self, email_message: EmailMessage, 
                              recipient_email: str,
                              reason: QuarantineReason,
                              risk_score: float,
                              confidence_score: float,
                              detection_engines: List[str],
                              admin_notes: str = "") -> str:
        """Quarantine an email message"""
        try:
            quarantine_id = str(uuid.uuid4())
            current_time = datetime.now(timezone.utc)
            
            # Calculate expiry time
            retention_days = self.config.get('default_retention_days', 30)
            expiry_time = current_time + timedelta(days=retention_days)
            
            # Store email message
            file_path = await self._store_email_message(quarantine_id, email_message)
            
            # Get message metadata
            original_message_id = email_message.get('Message-ID', f'<unknown-{quarantine_id}>')
            sender_email = email_message.get('From', 'unknown@unknown.com')
            subject = email_message.get('Subject', 'No Subject')
            
            # Calculate file size
            file_size = 0
            if file_path and Path(file_path).exists():
                file_size = Path(file_path).stat().st_size
            
            # Create quarantine item
            quarantine_item = QuarantineItem(
                quarantine_id=quarantine_id,
                original_message_id=original_message_id,
                recipient_email=recipient_email,
                sender_email=sender_email,
                subject=subject,
                quarantine_reason=reason,
                quarantine_timestamp=current_time,
                expiry_timestamp=expiry_time,
                status=QuarantineStatus.QUARANTINED,
                risk_score=risk_score,
                confidence_score=confidence_score,
                detection_engines=detection_engines,
                file_path=file_path,
                file_size=file_size,
                admin_notes=admin_notes,
                release_request_count=0,
                last_release_request=None,
                released_by=None,
                release_timestamp=None,
                tags=[]
            )
            
            # Store in database
            await self._store_quarantine_item(quarantine_item)
            
            # Log audit event
            await self._log_audit_event(
                quarantine_id, 'system', 'quarantine_email',
                f'Email quarantined: {reason.value}', None, None
            )
            
            # Send notification to user
            if self.config.get('notification_enabled', True):
                await self._send_quarantine_notification(quarantine_item)
            
            # Update statistics
            self.quarantine_stats['total_quarantined'] += 1
            
            logger.info(f"Email quarantined: {quarantine_id} for {recipient_email} ({reason.value})")
            return quarantine_id
            
        except Exception as e:
            logger.error(f"Error quarantining email: {str(e)}")
            raise
    
    async def _store_email_message(self, quarantine_id: str, email_message: EmailMessage) -> Optional[str]:
        """Store email message to quarantine storage"""
        try:
            # Create storage path
            date_path = datetime.now().strftime('%Y/%m/%d')
            storage_path = self.quarantine_storage / date_path
            storage_path.mkdir(parents=True, exist_ok=True)
            
            # Generate filename
            filename = f"{quarantine_id}.eml"
            file_path = storage_path / filename
            
            # Store email message
            with open(file_path, 'wb') as f:
                f.write(str(email_message).encode('utf-8'))
            
            logger.debug(f"Stored email message: {file_path}")
            return str(file_path)
            
        except Exception as e:
            logger.error(f"Error storing email message: {str(e)}")
            return None
    
    async def get_user_quarantine_items(self, user_email: str, 
                                       status_filter: Optional[QuarantineStatus] = None,
                                       limit: int = 100) -> List[QuarantineItem]:
        """Get quarantine items for a specific user"""
        try:
            query = '''
                SELECT * FROM quarantine_items 
                WHERE recipient_email = ?
            '''
            params = [user_email]
            
            if status_filter:
                query += ' AND status = ?'
                params.append(status_filter.value)
            
            query += ' ORDER BY quarantine_timestamp DESC LIMIT ?'
            params.append(limit)
            
            cursor = self.db_connection.execute(query, params)
            rows = cursor.fetchall()
            
            items = []
            for row in rows:
                item = self._row_to_quarantine_item(row)
                items.append(item)
            
            logger.debug(f"Retrieved {len(items)} quarantine items for {user_email}")
            return items
            
        except Exception as e:
            logger.error(f"Error getting user quarantine items: {str(e)}")
            return []
    
    async def request_email_release(self, quarantine_id: str, requesting_user: str,
                                   request_reason: str) -> bool:
        """Request release of quarantined email"""
        try:
            # Check if quarantine item exists and belongs to user
            quarantine_item = await self._get_quarantine_item(quarantine_id)
            if not quarantine_item:
                logger.warning(f"Quarantine item not found: {quarantine_id}")
                return False
            
            if quarantine_item.recipient_email != requesting_user:
                logger.warning(f"Unauthorized release request: {requesting_user} for {quarantine_id}")
                return False
            
            # Check daily request limit
            daily_requests = await self._get_daily_request_count(requesting_user)
            max_requests = self.config.get('max_release_requests_per_day', 10)
            
            if daily_requests >= max_requests:
                logger.warning(f"Daily request limit exceeded for {requesting_user}")
                return False
            
            # Check if item can be released
            if quarantine_item.status not in [QuarantineStatus.QUARANTINED, QuarantineStatus.PENDING_REVIEW]:
                logger.warning(f"Item cannot be released: {quarantine_id} ({quarantine_item.status})")
                return False
            
            # Create release request
            request_id = str(uuid.uuid4())
            current_time = datetime.now(timezone.utc)
            
            release_request = ReleaseRequest(
                request_id=request_id,
                quarantine_id=quarantine_id,
                requesting_user=requesting_user,
                request_reason=request_reason,
                request_timestamp=current_time,
                status='pending',
                reviewed_by=None,
                review_timestamp=None,
                review_decision=None,
                review_notes=None
            )
            
            # Store release request
            await self._store_release_request(release_request)
            
            # Update quarantine item
            quarantine_item.release_request_count += 1
            quarantine_item.last_release_request = current_time
            quarantine_item.status = QuarantineStatus.PENDING_REVIEW
            await self._store_quarantine_item(quarantine_item)
            
            # Log audit event
            await self._log_audit_event(
                quarantine_id, requesting_user, 'request_release',
                f'Release requested: {request_reason}', None, None
            )
            
            # Notify administrators if approval required
            if self.config.get('admin_approval_required', True):
                await self._notify_admin_release_request(release_request, quarantine_item)
            else:
                # Auto-approve if configured
                await self._approve_release_request(request_id, 'system', 'auto_approved', 'Automatic approval')
            
            logger.info(f"Release request created: {request_id} for {quarantine_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error requesting email release: {str(e)}")
            return False
    
    async def approve_release_request(self, request_id: str, reviewing_admin: str,
                                     decision: str, review_notes: str = "") -> bool:
        """Approve or deny a release request"""
        try:
            # Get release request
            release_request = await self._get_release_request(request_id)
            if not release_request:
                logger.warning(f"Release request not found: {request_id}")
                return False
            
            # Get quarantine item
            quarantine_item = await self._get_quarantine_item(release_request.quarantine_id)
            if not quarantine_item:
                logger.warning(f"Quarantine item not found: {release_request.quarantine_id}")
                return False
            
            # Update release request
            current_time = datetime.now(timezone.utc)
            release_request.reviewed_by = reviewing_admin
            release_request.review_timestamp = current_time
            release_request.review_decision = decision
            release_request.review_notes = review_notes
            release_request.status = 'completed'
            
            await self._store_release_request(release_request)
            
            # Handle approval decision
            if decision.lower() == 'approved':
                # Release the email
                success = await self._release_quarantined_email(
                    quarantine_item, reviewing_admin
                )
                
                if success:
                    # Send release notification to user
                    await self._send_release_notification(quarantine_item, True)
                
                return success
            
            else:
                # Deny the request
                quarantine_item.status = QuarantineStatus.QUARANTINED
                await self._store_quarantine_item(quarantine_item)
                
                # Send denial notification to user
                await self._send_release_notification(quarantine_item, False, review_notes)
                
                # Log audit event
                await self._log_audit_event(
                    quarantine_item.quarantine_id, reviewing_admin, 'deny_release',
                    f'Release denied: {review_notes}', None, None
                )
                
                return True
            
        except Exception as e:
            logger.error(f"Error approving release request: {str(e)}")
            return False
    
    async def _approve_release_request(self, request_id: str, reviewing_admin: str,
                                      decision: str, review_notes: str) -> bool:
        """Internal method to approve release request"""
        return await self.approve_release_request(request_id, reviewing_admin, decision, review_notes)
    
    async def _release_quarantined_email(self, quarantine_item: QuarantineItem,
                                        released_by: str) -> bool:
        """Release quarantined email back to recipient"""
        try:
            # Load original email message
            if not quarantine_item.file_path or not Path(quarantine_item.file_path).exists():
                logger.error(f"Email file not found: {quarantine_item.file_path}")
                return False
            
            # Read email content
            with open(quarantine_item.file_path, 'rb') as f:
                email_content = f.read()
            
            # Send email to recipient (would integrate with email provider)
            success = await self._deliver_email(
                quarantine_item.recipient_email,
                email_content,
                f"[RELEASED FROM QUARANTINE] {quarantine_item.subject}"
            )
            
            if success:
                # Update quarantine item
                current_time = datetime.now(timezone.utc)
                quarantine_item.status = QuarantineStatus.RELEASED
                quarantine_item.released_by = released_by
                quarantine_item.release_timestamp = current_time
                
                await self._store_quarantine_item(quarantine_item)
                
                # Log audit event
                await self._log_audit_event(
                    quarantine_item.quarantine_id, released_by, 'release_email',
                    'Email released from quarantine', None, None
                )
                
                # Update statistics
                self.quarantine_stats['total_released'] += 1
                
                logger.info(f"Email released: {quarantine_item.quarantine_id}")
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error releasing quarantined email: {str(e)}")
            return False
    
    async def _deliver_email(self, recipient: str, email_content: bytes, subject_prefix: str = "") -> bool:
        """Deliver email to recipient"""
        try:
            # This would integrate with email provider APIs
            # For now, just log the delivery
            logger.info(f"Email delivered to {recipient}: {subject_prefix}")
            return True
            
        except Exception as e:
            logger.error(f"Error delivering email: {str(e)}")
            return False
    
    async def send_quarantine_digest(self, user_email: str, digest_type: str = 'daily') -> bool:
        """Send quarantine digest to user"""
        try:
            # Get user preferences
            preferences = await self._get_user_preferences(user_email)
            if not preferences.enabled:
                return False
            
            # Check if user wants this digest type
            if digest_type == 'daily' and not preferences.daily_digest:
                return False
            elif digest_type == 'weekly' and not preferences.weekly_digest:
                return False
            
            # Get quarantine items for digest period
            if digest_type == 'daily':
                since = datetime.now(timezone.utc) - timedelta(days=1)
            else:  # weekly
                since = datetime.now(timezone.utc) - timedelta(days=7)
            
            items = await self._get_user_quarantine_items_since(user_email, since)
            
            if not items:
                return True  # No items to report
            
            # Generate digest content
            subject = f"Quarantine {digest_type.title()} Digest - {len(items)} items"
            
            html_content = self._generate_digest_html(items, digest_type, user_email)
            text_content = self._generate_digest_text(items, digest_type, user_email)
            
            # Send digest
            success = await self._send_email_notification(
                user_email, subject, text_content, html_content
            )
            
            if success:
                logger.info(f"Sent {digest_type} digest to {user_email}: {len(items)} items")
            
            return success
            
        except Exception as e:
            logger.error(f"Error sending quarantine digest: {str(e)}")
            return False
    
    def _generate_digest_html(self, items: List[QuarantineItem], digest_type: str, user_email: str) -> str:
        """Generate HTML content for quarantine digest"""
        try:
            web_url = self.config.get('web_interface_url', '#')
            
            html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Quarantine {digest_type.title()} Digest</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background-color: #f8f9fa; padding: 20px; border-radius: 5px; }}
        .item {{ border: 1px solid #dee2e6; padding: 15px; margin: 10px 0; border-radius: 5px; }}
        .high-risk {{ border-left: 5px solid #dc3545; }}
        .medium-risk {{ border-left: 5px solid #ffc107; }}
        .low-risk {{ border-left: 5px solid #28a745; }}
        .footer {{ margin-top: 30px; padding: 20px; background-color: #f8f9fa; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="header">
        <h2>Quarantine {digest_type.title()} Digest</h2>
        <p>You have {len(items)} quarantined emails in the past {digest_type}.</p>
    </div>
    
    <h3>Quarantined Items:</h3>
"""
            
            for item in items:
                risk_class = "high-risk" if item.risk_score > 7 else "medium-risk" if item.risk_score > 4 else "low-risk"
                
                html += f"""
    <div class="item {risk_class}">
        <h4>{item.subject}</h4>
        <p><strong>From:</strong> {item.sender_email}</p>
        <p><strong>Reason:</strong> {item.quarantine_reason.value.replace('_', ' ').title()}</p>
        <p><strong>Risk Score:</strong> {item.risk_score:.1f}/10</p>
        <p><strong>Quarantined:</strong> {item.quarantine_timestamp.strftime('%Y-%m-%d %H:%M UTC')}</p>
        <p><a href="{web_url}/item/{item.quarantine_id}">View Details</a> | 
           <a href="{web_url}/release/{item.quarantine_id}">Request Release</a></p>
    </div>
"""
            
            html += f"""
    <div class="footer">
        <p>This is an automated message from ISECTECH Email Security.</p>
        <p>To manage your quarantine preferences, visit: <a href="{web_url}/preferences">{web_url}/preferences</a></p>
        <p>For support, contact: security@isectech.com</p>
    </div>
</body>
</html>
"""
            
            return html
            
        except Exception as e:
            logger.error(f"Error generating digest HTML: {str(e)}")
            return ""
    
    def _generate_digest_text(self, items: List[QuarantineItem], digest_type: str, user_email: str) -> str:
        """Generate text content for quarantine digest"""
        try:
            web_url = self.config.get('web_interface_url', '#')
            
            text = f"""
QUARANTINE {digest_type.upper()} DIGEST
=================================

You have {len(items)} quarantined emails in the past {digest_type}.

QUARANTINED ITEMS:
"""
            
            for i, item in enumerate(items, 1):
                text += f"""
{i}. {item.subject}
   From: {item.sender_email}
   Reason: {item.quarantine_reason.value.replace('_', ' ').title()}
   Risk Score: {item.risk_score:.1f}/10
   Quarantined: {item.quarantine_timestamp.strftime('%Y-%m-%d %H:%M UTC')}
   View: {web_url}/item/{item.quarantine_id}
   
"""
            
            text += f"""
ACTIONS:
- View all quarantined items: {web_url}
- Manage preferences: {web_url}/preferences
- Contact support: security@isectech.com

This is an automated message from ISECTECH Email Security.
"""
            
            return text
            
        except Exception as e:
            logger.error(f"Error generating digest text: {str(e)}")
            return ""
    
    async def _send_quarantine_notification(self, quarantine_item: QuarantineItem):
        """Send immediate quarantine notification"""
        try:
            preferences = await self._get_user_preferences(quarantine_item.recipient_email)
            if not preferences.immediate_notifications:
                return
            
            subject = f"Email Quarantined - {quarantine_item.quarantine_reason.value.replace('_', ' ').title()}"
            
            # Generate notification content
            web_url = self.config.get('web_interface_url', '#')
            
            text_content = f"""
An email sent to you has been quarantined by ISECTECH Email Security.

DETAILS:
Subject: {quarantine_item.subject}
From: {quarantine_item.sender_email}
Reason: {quarantine_item.quarantine_reason.value.replace('_', ' ').title()}
Risk Score: {quarantine_item.risk_score:.1f}/10
Quarantined: {quarantine_item.quarantine_timestamp.strftime('%Y-%m-%d %H:%M UTC')}

ACTIONS:
- View details: {web_url}/item/{quarantine_item.quarantine_id}
- Request release: {web_url}/release/{quarantine_item.quarantine_id}
- Manage preferences: {web_url}/preferences

If you believe this is a legitimate email, you can request its release.

ISECTECH Email Security
"""
            
            html_content = f"""
<div style="font-family: Arial, sans-serif; max-width: 600px;">
    <h2 style="color: #dc3545;">Email Quarantined</h2>
    
    <p>An email sent to you has been quarantined by ISECTECH Email Security.</p>
    
    <div style="background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin: 20px 0;">
        <h3>Details:</h3>
        <p><strong>Subject:</strong> {quarantine_item.subject}</p>
        <p><strong>From:</strong> {quarantine_item.sender_email}</p>
        <p><strong>Reason:</strong> {quarantine_item.quarantine_reason.value.replace('_', ' ').title()}</p>
        <p><strong>Risk Score:</strong> {quarantine_item.risk_score:.1f}/10</p>
        <p><strong>Quarantined:</strong> {quarantine_item.quarantine_timestamp.strftime('%Y-%m-%d %H:%M UTC')}</p>
    </div>
    
    <div style="margin: 20px 0;">
        <a href="{web_url}/item/{quarantine_item.quarantine_id}" 
           style="background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; margin-right: 10px;">
           View Details
        </a>
        <a href="{web_url}/release/{quarantine_item.quarantine_id}"
           style="background-color: #28a745; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">
           Request Release
        </a>
    </div>
    
    <p><small>If you believe this is a legitimate email, you can request its release.</small></p>
    
    <div style="margin-top: 30px; font-size: 12px; color: #6c757d;">
        <p>ISECTECH Email Security | <a href="{web_url}/preferences">Manage Preferences</a></p>
    </div>
</div>
"""
            
            success = await self._send_email_notification(
                quarantine_item.recipient_email, subject, text_content, html_content
            )
            
            if success:
                logger.info(f"Quarantine notification sent to {quarantine_item.recipient_email}")
            
        except Exception as e:
            logger.error(f"Error sending quarantine notification: {str(e)}")
    
    async def _send_release_notification(self, quarantine_item: QuarantineItem, 
                                        approved: bool, reason: str = ""):
        """Send release request notification"""
        try:
            preferences = await self._get_user_preferences(quarantine_item.recipient_email)
            if not preferences.release_notifications:
                return
            
            if approved:
                subject = "Email Released from Quarantine"
                message = f"""
Your quarantined email has been released and delivered to your inbox.

DETAILS:
Subject: {quarantine_item.subject}
From: {quarantine_item.sender_email}
Released: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}

The email should now be available in your inbox.

ISECTECH Email Security
"""
            else:
                subject = "Email Release Request Denied"
                message = f"""
Your request to release a quarantined email has been denied.

DETAILS:
Subject: {quarantine_item.subject}
From: {quarantine_item.sender_email}
Reason for denial: {reason}

If you have questions about this decision, please contact security@isectech.com.

ISECTECH Email Security
"""
            
            success = await self._send_email_notification(
                quarantine_item.recipient_email, subject, message
            )
            
            if success:
                logger.info(f"Release notification sent to {quarantine_item.recipient_email}")
            
        except Exception as e:
            logger.error(f"Error sending release notification: {str(e)}")
    
    async def _notify_admin_release_request(self, release_request: ReleaseRequest,
                                           quarantine_item: QuarantineItem):
        """Notify administrators of release request"""
        try:
            admin_emails = self.config.get('admin_emails', ['admin@isectech.com'])
            web_url = self.config.get('web_interface_url', '#')
            
            subject = f"Release Request - {quarantine_item.quarantine_reason.value.replace('_', ' ').title()}"
            
            message = f"""
A user has requested release of a quarantined email.

REQUEST DETAILS:
Request ID: {release_request.request_id}
User: {release_request.requesting_user}
Reason: {release_request.request_reason}
Requested: {release_request.request_timestamp.strftime('%Y-%m-%d %H:%M UTC')}

EMAIL DETAILS:
Subject: {quarantine_item.subject}
From: {quarantine_item.sender_email}
Quarantine Reason: {quarantine_item.quarantine_reason.value.replace('_', ' ').title()}
Risk Score: {quarantine_item.risk_score:.1f}/10
Confidence: {quarantine_item.confidence_score:.1f}

ACTIONS:
- Review request: {web_url}/admin/review/{release_request.request_id}
- View quarantine item: {web_url}/admin/item/{quarantine_item.quarantine_id}

Please review and approve/deny this request.

ISECTECH Email Security System
"""
            
            for admin_email in admin_emails:
                await self._send_email_notification(admin_email, subject, message)
                
            logger.info(f"Admin notification sent for release request {release_request.request_id}")
            
        except Exception as e:
            logger.error(f"Error notifying admin of release request: {str(e)}")
    
    async def _send_email_notification(self, recipient: str, subject: str, 
                                      text_content: str, html_content: str = None) -> bool:
        """Send email notification"""
        try:
            if not self.config.get('notification_enabled', True):
                return False
            
            # This would integrate with SMTP server or email service
            logger.info(f"Email notification sent to {recipient}: {subject}")
            
            # Log notification
            notification_id = str(uuid.uuid4())
            await self._log_notification(
                notification_id, recipient, NotificationType.QUARANTINE_NOTIFICATION.value,
                subject, True
            )
            
            return True
            
        except Exception as e:
            logger.error(f"Error sending email notification: {str(e)}")
            return False
    
    async def get_admin_dashboard_stats(self) -> AdminDashboardStats:
        """Get administrative dashboard statistics"""
        try:
            current_time = datetime.now(timezone.utc)
            today_start = current_time.replace(hour=0, minute=0, second=0, microsecond=0)
            week_start = today_start - timedelta(days=7)
            
            # Total quarantined
            cursor = self.db_connection.execute('SELECT COUNT(*) FROM quarantine_items')
            total_quarantined = cursor.fetchone()[0]
            
            # Quarantined today
            cursor = self.db_connection.execute(
                'SELECT COUNT(*) FROM quarantine_items WHERE quarantine_timestamp >= ?',
                (today_start.timestamp(),)
            )
            quarantined_today = cursor.fetchone()[0]
            
            # Quarantined this week
            cursor = self.db_connection.execute(
                'SELECT COUNT(*) FROM quarantine_items WHERE quarantine_timestamp >= ?',
                (week_start.timestamp(),)
            )
            quarantined_this_week = cursor.fetchone()[0]
            
            # Pending review
            cursor = self.db_connection.execute(
                'SELECT COUNT(*) FROM quarantine_items WHERE status = ?',
                (QuarantineStatus.PENDING_REVIEW.value,)
            )
            pending_review = cursor.fetchone()[0]
            
            # Top reasons
            cursor = self.db_connection.execute('''
                SELECT quarantine_reason, COUNT(*) as count 
                FROM quarantine_items 
                WHERE quarantine_timestamp >= ?
                GROUP BY quarantine_reason 
                ORDER BY count DESC 
                LIMIT 5
            ''', (week_start.timestamp(),))
            top_reasons = dict(cursor.fetchall())
            
            # Top senders
            cursor = self.db_connection.execute('''
                SELECT sender_email, COUNT(*) as count 
                FROM quarantine_items 
                WHERE quarantine_timestamp >= ?
                GROUP BY sender_email 
                ORDER BY count DESC 
                LIMIT 5
            ''', (week_start.timestamp(),))
            top_senders = dict(cursor.fetchall())
            
            # Calculate storage usage
            storage_usage_mb = self._calculate_storage_usage()
            
            # Calculate false positive rate
            cursor = self.db_connection.execute(
                'SELECT COUNT(*) FROM quarantine_items WHERE status = ?',
                (QuarantineStatus.FALSE_POSITIVE.value,)
            )
            false_positives = cursor.fetchone()[0]
            false_positive_rate = (false_positives / max(total_quarantined, 1)) * 100
            
            return AdminDashboardStats(
                total_quarantined=total_quarantined,
                quarantined_today=quarantined_today,
                quarantined_this_week=quarantined_this_week,
                pending_review=pending_review,
                top_reasons=top_reasons,
                top_senders=top_senders,
                avg_processing_time=0.0,  # Would calculate from audit logs
                false_positive_rate=false_positive_rate,
                storage_usage_mb=storage_usage_mb
            )
            
        except Exception as e:
            logger.error(f"Error getting admin dashboard stats: {str(e)}")
            return AdminDashboardStats(
                total_quarantined=0, quarantined_today=0, quarantined_this_week=0,
                pending_review=0, top_reasons={}, top_senders={},
                avg_processing_time=0.0, false_positive_rate=0.0, storage_usage_mb=0.0
            )
    
    def _calculate_storage_usage(self) -> float:
        """Calculate total storage usage in MB"""
        try:
            total_size = 0
            for file_path in self.quarantine_storage.rglob('*.eml'):
                if file_path.is_file():
                    total_size += file_path.stat().st_size
            
            return total_size / (1024 * 1024)  # Convert to MB
            
        except Exception as e:
            logger.error(f"Error calculating storage usage: {str(e)}")
            return 0.0
    
    async def cleanup_expired_items(self) -> int:
        """Clean up expired quarantine items"""
        try:
            current_time = datetime.now(timezone.utc)
            
            # Find expired items
            cursor = self.db_connection.execute(
                'SELECT quarantine_id, file_path FROM quarantine_items WHERE expiry_timestamp < ?',
                (current_time.timestamp(),)
            )
            expired_items = cursor.fetchall()
            
            cleaned_count = 0
            
            for quarantine_id, file_path in expired_items:
                try:
                    # Delete file
                    if file_path and Path(file_path).exists():
                        Path(file_path).unlink()
                    
                    # Update status
                    self.db_connection.execute(
                        'UPDATE quarantine_items SET status = ? WHERE quarantine_id = ?',
                        (QuarantineStatus.EXPIRED.value, quarantine_id)
                    )
                    
                    cleaned_count += 1
                    
                except Exception as e:
                    logger.warning(f"Error cleaning up item {quarantine_id}: {str(e)}")
            
            self.db_connection.commit()
            
            if cleaned_count > 0:
                logger.info(f"Cleaned up {cleaned_count} expired quarantine items")
            
            return cleaned_count
            
        except Exception as e:
            logger.error(f"Error cleaning up expired items: {str(e)}")
            return 0
    
    # Database helper methods
    async def _store_quarantine_item(self, item: QuarantineItem):
        """Store quarantine item in database"""
        self.db_connection.execute('''
            INSERT OR REPLACE INTO quarantine_items
            (quarantine_id, original_message_id, recipient_email, sender_email,
             subject, quarantine_reason, quarantine_timestamp, expiry_timestamp,
             status, risk_score, confidence_score, detection_engines, file_path,
             file_size, admin_notes, release_request_count, last_release_request,
             released_by, release_timestamp, tags)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            item.quarantine_id, item.original_message_id, item.recipient_email,
            item.sender_email, item.subject, item.quarantine_reason.value,
            item.quarantine_timestamp.timestamp(), item.expiry_timestamp.timestamp(),
            item.status.value, item.risk_score, item.confidence_score,
            json.dumps(item.detection_engines), item.file_path, item.file_size,
            item.admin_notes, item.release_request_count,
            item.last_release_request.timestamp() if item.last_release_request else None,
            item.released_by, 
            item.release_timestamp.timestamp() if item.release_timestamp else None,
            json.dumps(item.tags)
        ))
        self.db_connection.commit()
    
    async def _get_quarantine_item(self, quarantine_id: str) -> Optional[QuarantineItem]:
        """Get quarantine item by ID"""
        cursor = self.db_connection.execute(
            'SELECT * FROM quarantine_items WHERE quarantine_id = ?',
            (quarantine_id,)
        )
        row = cursor.fetchone()
        return self._row_to_quarantine_item(row) if row else None
    
    def _row_to_quarantine_item(self, row) -> QuarantineItem:
        """Convert database row to QuarantineItem"""
        return QuarantineItem(
            quarantine_id=row[0],
            original_message_id=row[1],
            recipient_email=row[2],
            sender_email=row[3],
            subject=row[4],
            quarantine_reason=QuarantineReason(row[5]),
            quarantine_timestamp=datetime.fromtimestamp(row[6], tz=timezone.utc),
            expiry_timestamp=datetime.fromtimestamp(row[7], tz=timezone.utc),
            status=QuarantineStatus(row[8]),
            risk_score=row[9],
            confidence_score=row[10],
            detection_engines=json.loads(row[11]) if row[11] else [],
            file_path=row[12],
            file_size=row[13],
            admin_notes=row[14],
            release_request_count=row[15],
            last_release_request=datetime.fromtimestamp(row[16], tz=timezone.utc) if row[16] else None,
            released_by=row[17],
            release_timestamp=datetime.fromtimestamp(row[18], tz=timezone.utc) if row[18] else None,
            tags=json.loads(row[19]) if row[19] else []
        )
    
    async def _store_release_request(self, request: ReleaseRequest):
        """Store release request in database"""
        self.db_connection.execute('''
            INSERT OR REPLACE INTO release_requests
            (request_id, quarantine_id, requesting_user, request_reason,
             request_timestamp, status, reviewed_by, review_timestamp,
             review_decision, review_notes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            request.request_id, request.quarantine_id, request.requesting_user,
            request.request_reason, request.request_timestamp.timestamp(),
            request.status, request.reviewed_by,
            request.review_timestamp.timestamp() if request.review_timestamp else None,
            request.review_decision, request.review_notes
        ))
        self.db_connection.commit()
    
    async def _get_release_request(self, request_id: str) -> Optional[ReleaseRequest]:
        """Get release request by ID"""
        cursor = self.db_connection.execute(
            'SELECT * FROM release_requests WHERE request_id = ?',
            (request_id,)
        )
        row = cursor.fetchone()
        if not row:
            return None
        
        return ReleaseRequest(
            request_id=row[0],
            quarantine_id=row[1],
            requesting_user=row[2],
            request_reason=row[3],
            request_timestamp=datetime.fromtimestamp(row[4], tz=timezone.utc),
            status=row[5],
            reviewed_by=row[6],
            review_timestamp=datetime.fromtimestamp(row[7], tz=timezone.utc) if row[7] else None,
            review_decision=row[8],
            review_notes=row[9]
        )
    
    async def _get_user_preferences(self, user_email: str) -> NotificationPreferences:
        """Get user notification preferences"""
        if user_email in self.user_preferences:
            return self.user_preferences[user_email]
        
        cursor = self.db_connection.execute(
            'SELECT * FROM notification_preferences WHERE user_email = ?',
            (user_email,)
        )
        row = cursor.fetchone()
        
        if row:
            preferences = NotificationPreferences(
                user_email=row[0],
                immediate_notifications=bool(row[1]),
                daily_digest=bool(row[2]),
                weekly_digest=bool(row[3]),
                release_notifications=bool(row[4]),
                admin_alerts=bool(row[5]),
                preferred_time=row[6],
                timezone=row[7],
                enabled=bool(row[8])
            )
        else:
            # Create default preferences
            preferences = NotificationPreferences(
                user_email=user_email,
                immediate_notifications=True,
                daily_digest=True,
                weekly_digest=False,
                release_notifications=True,
                admin_alerts=False,
                preferred_time="09:00",
                timezone="UTC",
                enabled=True
            )
            
            # Store default preferences
            self.db_connection.execute('''
                INSERT INTO notification_preferences
                (user_email, immediate_notifications, daily_digest, weekly_digest,
                 release_notifications, admin_alerts, preferred_time, timezone, enabled)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                user_email, preferences.immediate_notifications,
                preferences.daily_digest, preferences.weekly_digest,
                preferences.release_notifications, preferences.admin_alerts,
                preferences.preferred_time, preferences.timezone,
                preferences.enabled
            ))
            self.db_connection.commit()
        
        # Cache preferences
        self.user_preferences[user_email] = preferences
        return preferences
    
    async def _get_daily_request_count(self, user_email: str) -> int:
        """Get user's daily release request count"""
        today_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
        cursor = self.db_connection.execute('''
            SELECT COUNT(*) FROM release_requests 
            WHERE requesting_user = ? AND request_timestamp >= ?
        ''', (user_email, today_start.timestamp()))
        return cursor.fetchone()[0]
    
    async def _get_user_quarantine_items_since(self, user_email: str, since: datetime) -> List[QuarantineItem]:
        """Get user quarantine items since specified time"""
        cursor = self.db_connection.execute('''
            SELECT * FROM quarantine_items 
            WHERE recipient_email = ? AND quarantine_timestamp >= ?
            ORDER BY quarantine_timestamp DESC
        ''', (user_email, since.timestamp()))
        
        items = []
        for row in cursor.fetchall():
            items.append(self._row_to_quarantine_item(row))
        
        return items
    
    async def _log_notification(self, notification_id: str, user_email: str,
                               notification_type: str, subject: str, success: bool):
        """Log notification delivery"""
        self.db_connection.execute('''
            INSERT INTO notification_log
            (notification_id, user_email, notification_type, subject,
             sent_timestamp, delivery_status, retry_count)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            notification_id, user_email, notification_type, subject,
            datetime.now(timezone.utc).timestamp(),
            'sent' if success else 'failed', 0
        ))
        self.db_connection.commit()
    
    async def _log_audit_event(self, quarantine_id: Optional[str], user_email: str,
                              action: str, details: str, ip_address: Optional[str],
                              user_agent: Optional[str]):
        """Log audit event"""
        audit_id = str(uuid.uuid4())
        self.db_connection.execute('''
            INSERT INTO audit_log
            (audit_id, quarantine_id, user_email, action, details,
             timestamp, ip_address, user_agent)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            audit_id, quarantine_id, user_email, action, details,
            datetime.now(timezone.utc).timestamp(), ip_address, user_agent
        ))
        self.db_connection.commit()
    
    def get_quarantine_statistics(self) -> Dict[str, Any]:
        """Get quarantine system statistics"""
        try:
            return {
                'total_quarantined': self.quarantine_stats['total_quarantined'],
                'total_released': self.quarantine_stats['total_released'],
                'false_positives': self.quarantine_stats['false_positives'],
                'avg_storage_time': self.quarantine_stats['avg_storage_time'],
                'user_satisfaction': self.quarantine_stats['user_satisfaction'],
                'storage_usage_mb': self._calculate_storage_usage()
            }
            
        except Exception as e:
            logger.error(f"Error getting quarantine statistics: {str(e)}")
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
    """Example usage of QuarantineManager"""
    
    try:
        async with QuarantineManager() as quarantine_manager:
            # Create test email message
            test_email = EmailMessage()
            test_email['From'] = 'phishing@suspicious.com'
            test_email['To'] = 'user@isectech.com'
            test_email['Subject'] = 'Urgent: Verify your account immediately'
            test_email['Message-ID'] = '<test123@suspicious.com>'
            test_email.set_content('Click here to verify your account before it gets suspended!')
            
            # Quarantine the email
            quarantine_id = await quarantine_manager.quarantine_email(
                email_message=test_email,
                recipient_email='user@isectech.com',
                reason=QuarantineReason.PHISHING_DETECTED,
                risk_score=8.5,
                confidence_score=0.9,
                detection_engines=['phishing_detector', 'url_analyzer'],
                admin_notes='High-confidence phishing detection'
            )
            
            print(f"Email quarantined: {quarantine_id}")
            
            # Get user quarantine items
            items = await quarantine_manager.get_user_quarantine_items('user@isectech.com')
            print(f"User has {len(items)} quarantined items")
            
            # Request release
            success = await quarantine_manager.request_email_release(
                quarantine_id, 'user@isectech.com', 'This looks like a legitimate email from my bank'
            )
            print(f"Release request: {'Success' if success else 'Failed'}")
            
            # Get admin stats
            stats = await quarantine_manager.get_admin_dashboard_stats()
            print(f"Admin Stats:")
            print(f"  Total Quarantined: {stats.total_quarantined}")
            print(f"  Pending Review: {stats.pending_review}")
            print(f"  Storage Usage: {stats.storage_usage_mb:.2f} MB")
            
            # Send digest
            await quarantine_manager.send_quarantine_digest('user@isectech.com', 'daily')
            
            # Cleanup expired items
            cleaned = await quarantine_manager.cleanup_expired_items()
            print(f"Cleaned up {cleaned} expired items")
        
    except Exception as e:
        logger.error(f"Error in example: {str(e)}")


if __name__ == "__main__":
    asyncio.run(main())