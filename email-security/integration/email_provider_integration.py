"""
Email Provider Integration Engine for ISECTECH Email Security Integration

This module provides comprehensive integration with major email providers including:
- Microsoft 365 (Exchange Online, Outlook) API integration
- Google Workspace (Gmail) API integration  
- Real-time email monitoring and webhook handling
- Bulk email processing and management
- OAuth2 authentication and token management
- Production-grade performance and reliability

Author: ISECTECH Security Team
Version: 1.0.0
"""

import asyncio
import json
import logging
import sqlite3
import uuid
import base64
import hashlib
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Set, Union
from dataclasses import dataclass, asdict
from enum import Enum
import aiohttp
import jwt
from email.message import EmailMessage
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import urllib.parse

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ProviderType(Enum):
    """Email provider types"""
    MICROSOFT_365 = "microsoft_365"
    GOOGLE_WORKSPACE = "google_workspace"
    EXCHANGE_ONPREM = "exchange_onprem"
    IMAP_GENERIC = "imap_generic"


class IntegrationStatus(Enum):
    """Integration connection status"""
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    AUTHENTICATING = "authenticating"
    ERROR = "error"
    RATE_LIMITED = "rate_limited"
    MAINTENANCE = "maintenance"


class EmailAction(Enum):
    """Email management actions"""
    MOVE_TO_FOLDER = "move_to_folder"
    DELETE = "delete"
    MARK_AS_READ = "mark_as_read"
    MARK_AS_SPAM = "mark_as_spam"
    QUARANTINE = "quarantine"
    ADD_LABEL = "add_label"
    FORWARD = "forward"
    BLOCK_SENDER = "block_sender"


@dataclass
class OAuth2Credentials:
    """OAuth2 authentication credentials"""
    client_id: str
    client_secret: str
    tenant_id: Optional[str]  # For Microsoft 365
    access_token: Optional[str]
    refresh_token: Optional[str]
    token_expires: Optional[datetime]
    scopes: List[str]


@dataclass
class EmailProviderConfig:
    """Email provider configuration"""
    provider_id: str
    provider_type: ProviderType
    display_name: str
    credentials: OAuth2Credentials
    api_endpoints: Dict[str, str]
    rate_limits: Dict[str, int]
    webhook_url: Optional[str]
    enabled: bool
    last_sync: Optional[datetime]


@dataclass
class EmailMetadata:
    """Email metadata from provider"""
    provider_message_id: str
    provider_thread_id: Optional[str]
    folder_path: str
    labels: List[str]
    is_read: bool
    is_flagged: bool
    received_datetime: datetime
    size_bytes: int
    has_attachments: bool
    importance: str
    sensitivity: str


@dataclass
class EmailMessage:
    """Enhanced email message with provider metadata"""
    message_id: str
    provider_metadata: EmailMetadata
    from_address: str
    to_addresses: List[str]
    cc_addresses: List[str]
    bcc_addresses: List[str]
    subject: str
    body_text: Optional[str]
    body_html: Optional[str]
    attachments: List[Dict[str, Any]]
    headers: Dict[str, str]
    raw_message: Optional[bytes]


@dataclass
class BulkOperationResult:
    """Result of bulk email operation"""
    operation_id: str
    total_messages: int
    processed_messages: int
    successful_operations: int
    failed_operations: int
    errors: List[str]
    processing_duration: float


@dataclass
class IntegrationHealth:
    """Provider integration health status"""
    provider_id: str
    status: IntegrationStatus
    last_successful_request: Optional[datetime]
    total_requests: int
    successful_requests: int
    failed_requests: int
    rate_limit_hits: int
    current_quota_usage: Dict[str, int]
    error_rate: float


class EmailProviderIntegration:
    """
    Advanced email provider integration engine
    
    Provides unified interface for managing emails across multiple providers
    with OAuth2 authentication, rate limiting, and bulk operations.
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        """Initialize email provider integration"""
        self.config = config or self._get_default_config()
        self.data_dir = Path(self.config.get('data_directory', '/tmp/email_integration'))
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        # Provider configurations
        self.providers: Dict[str, EmailProviderConfig] = {}
        
        # HTTP session for API calls
        self.session: Optional[aiohttp.ClientSession] = None
        
        # Rate limiting and health monitoring
        self.rate_limiters: Dict[str, Dict[str, datetime]] = {}
        self.health_status: Dict[str, IntegrationHealth] = {}
        
        # Initialize database
        self._init_database()
        
        # Performance tracking
        self.integration_stats = {
            'total_messages_processed': 0,
            'total_api_calls': 0,
            'total_errors': 0,
            'provider_performance': {}
        }
        
        logger.info("Email Provider Integration initialized")
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration"""
        return {
            'data_directory': '/tmp/email_integration',
            'request_timeout': 30,
            'max_concurrent_requests': 10,
            'retry_attempts': 3,
            'rate_limit_buffer': 0.1,  # 10% buffer below actual limits
            'token_refresh_buffer_minutes': 5,
            'webhook_verification_timeout': 30,
            'bulk_operation_batch_size': 100,
            'enable_webhook_verification': True,
            'store_raw_messages': False
        }
    
    def _init_database(self):
        """Initialize SQLite database for integration data"""
        db_path = self.data_dir / 'email_integration.db'
        self.db_connection = sqlite3.connect(str(db_path), check_same_thread=False)
        
        self.db_connection.execute('''
            CREATE TABLE IF NOT EXISTS providers (
                provider_id TEXT PRIMARY KEY,
                provider_type TEXT,
                display_name TEXT,
                credentials TEXT,
                api_endpoints TEXT,
                rate_limits TEXT,
                webhook_url TEXT,
                enabled BOOLEAN,
                last_sync REAL,
                created_timestamp REAL
            )
        ''')
        
        self.db_connection.execute('''
            CREATE TABLE IF NOT EXISTS processed_messages (
                message_id TEXT PRIMARY KEY,
                provider_id TEXT,
                provider_message_id TEXT,
                processed_timestamp REAL,
                folder_path TEXT,
                action_taken TEXT,
                processing_duration REAL
            )
        ''')
        
        self.db_connection.execute('''
            CREATE TABLE IF NOT EXISTS bulk_operations (
                operation_id TEXT PRIMARY KEY,
                provider_id TEXT,
                operation_type TEXT,
                total_messages INTEGER,
                processed_messages INTEGER,
                successful_operations INTEGER,
                failed_operations INTEGER,
                start_timestamp REAL,
                completion_timestamp REAL,
                errors TEXT
            )
        ''')
        
        self.db_connection.execute('''
            CREATE TABLE IF NOT EXISTS api_calls (
                call_id TEXT PRIMARY KEY,
                provider_id TEXT,
                endpoint TEXT,
                method TEXT,
                response_code INTEGER,
                response_time REAL,
                timestamp REAL,
                error_message TEXT
            )
        ''')
        
        self.db_connection.commit()
    
    async def __aenter__(self):
        """Async context manager entry"""
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.config.get('request_timeout', 30)),
            connector=aiohttp.TCPConnector(limit=self.config.get('max_concurrent_requests', 10))
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()
    
    async def add_provider(self, provider_config: EmailProviderConfig) -> bool:
        """Add email provider configuration"""
        try:
            # Validate configuration
            if not await self._validate_provider_config(provider_config):
                logger.error(f"Invalid provider configuration: {provider_config.provider_id}")
                return False
            
            # Test connection
            if not await self._test_provider_connection(provider_config):
                logger.error(f"Failed to connect to provider: {provider_config.provider_id}")
                return False
            
            # Store configuration
            self.providers[provider_config.provider_id] = provider_config
            await self._store_provider_config(provider_config)
            
            # Initialize health monitoring
            self.health_status[provider_config.provider_id] = IntegrationHealth(
                provider_id=provider_config.provider_id,
                status=IntegrationStatus.CONNECTED,
                last_successful_request=datetime.now(timezone.utc),
                total_requests=0,
                successful_requests=0,
                failed_requests=0,
                rate_limit_hits=0,
                current_quota_usage={},
                error_rate=0.0
            )
            
            # Initialize rate limiting
            self.rate_limiters[provider_config.provider_id] = {}
            
            logger.info(f"Successfully added provider: {provider_config.display_name}")
            return True
            
        except Exception as e:
            logger.error(f"Error adding provider {provider_config.provider_id}: {str(e)}")
            return False
    
    async def _validate_provider_config(self, config: EmailProviderConfig) -> bool:
        """Validate provider configuration"""
        try:
            # Check required fields
            if not config.provider_id or not config.provider_type:
                return False
            
            if not config.credentials.client_id or not config.credentials.client_secret:
                return False
            
            # Microsoft 365 specific validation
            if config.provider_type == ProviderType.MICROSOFT_365:
                if not config.credentials.tenant_id:
                    return False
                
                required_endpoints = ['auth_url', 'token_url', 'graph_api_url']
                if not all(endpoint in config.api_endpoints for endpoint in required_endpoints):
                    return False
            
            # Google Workspace specific validation
            elif config.provider_type == ProviderType.GOOGLE_WORKSPACE:
                required_endpoints = ['auth_url', 'token_url', 'gmail_api_url']
                if not all(endpoint in config.api_endpoints for endpoint in required_endpoints):
                    return False
            
            return True
            
        except Exception as e:
            logger.error(f"Error validating provider config: {str(e)}")
            return False
    
    async def _test_provider_connection(self, config: EmailProviderConfig) -> bool:
        """Test connection to email provider"""
        try:
            if config.provider_type == ProviderType.MICROSOFT_365:
                return await self._test_microsoft_365_connection(config)
            elif config.provider_type == ProviderType.GOOGLE_WORKSPACE:
                return await self._test_google_workspace_connection(config)
            else:
                logger.warning(f"Connection test not implemented for {config.provider_type}")
                return True
                
        except Exception as e:
            logger.error(f"Error testing provider connection: {str(e)}")
            return False
    
    async def _test_microsoft_365_connection(self, config: EmailProviderConfig) -> bool:
        """Test Microsoft 365 connection"""
        try:
            # Attempt to get access token
            token = await self._get_microsoft_365_token(config)
            if not token:
                return False
            
            # Test API call
            headers = {
                'Authorization': f'Bearer {token}',
                'Content-Type': 'application/json'
            }
            
            async with self.session.get(
                f"{config.api_endpoints['graph_api_url']}/v1.0/me",
                headers=headers
            ) as response:
                return response.status == 200
                
        except Exception as e:
            logger.error(f"Microsoft 365 connection test failed: {str(e)}")
            return False
    
    async def _test_google_workspace_connection(self, config: EmailProviderConfig) -> bool:
        """Test Google Workspace connection"""
        try:
            # Attempt to get access token
            token = await self._get_google_workspace_token(config)
            if not token:
                return False
            
            # Test API call
            headers = {
                'Authorization': f'Bearer {token}',
                'Content-Type': 'application/json'
            }
            
            async with self.session.get(
                f"{config.api_endpoints['gmail_api_url']}/gmail/v1/users/me/profile",
                headers=headers
            ) as response:
                return response.status == 200
                
        except Exception as e:
            logger.error(f"Google Workspace connection test failed: {str(e)}")
            return False
    
    async def get_emails(self, provider_id: str, 
                        folder_path: str = "INBOX",
                        limit: int = 100,
                        since: Optional[datetime] = None) -> List[EmailMessage]:
        """Get emails from provider"""
        try:
            provider = self.providers.get(provider_id)
            if not provider:
                raise ValueError(f"Provider not found: {provider_id}")
            
            # Check rate limits
            if not await self._check_rate_limit(provider_id, 'get_emails'):
                raise Exception("Rate limit exceeded")
            
            # Get emails based on provider type
            if provider.provider_type == ProviderType.MICROSOFT_365:
                emails = await self._get_microsoft_365_emails(provider, folder_path, limit, since)
            elif provider.provider_type == ProviderType.GOOGLE_WORKSPACE:
                emails = await self._get_google_workspace_emails(provider, folder_path, limit, since)
            else:
                raise ValueError(f"Unsupported provider type: {provider.provider_type}")
            
            # Update health status
            await self._update_health_status(provider_id, True)
            
            logger.info(f"Retrieved {len(emails)} emails from {provider.display_name}")
            return emails
            
        except Exception as e:
            await self._update_health_status(provider_id, False, str(e))
            logger.error(f"Error getting emails from {provider_id}: {str(e)}")
            raise
    
    async def _get_microsoft_365_emails(self, provider: EmailProviderConfig,
                                       folder_path: str, limit: int,
                                       since: Optional[datetime]) -> List[EmailMessage]:
        """Get emails from Microsoft 365"""
        try:
            token = await self._get_microsoft_365_token(provider)
            headers = {
                'Authorization': f'Bearer {token}',
                'Content-Type': 'application/json'
            }
            
            # Build API URL
            api_url = f"{provider.api_endpoints['graph_api_url']}/v1.0/me/mailFolders"
            
            # Get folder ID if not using wellKnownName
            if folder_path != "INBOX":
                folder_id = await self._get_microsoft_folder_id(provider, folder_path, headers)
                if not folder_id:
                    raise ValueError(f"Folder not found: {folder_path}")
                api_url += f"/{folder_id}"
            else:
                api_url += "/inbox"
            
            api_url += "/messages"
            
            # Add query parameters
            params = {
                '$top': limit,
                '$select': 'id,subject,from,toRecipients,ccRecipients,bccRecipients,'
                          'receivedDateTime,hasAttachments,importance,bodyPreview,body',
                '$expand': 'attachments($select=id,name,size,contentType)'
            }
            
            if since:
                params['$filter'] = f"receivedDateTime ge {since.isoformat()}"
            
            # Make API request
            async with self.session.get(api_url, headers=headers, params=params) as response:
                if response.status != 200:
                    raise Exception(f"API request failed: {response.status}")
                
                data = await response.json()
                emails = []
                
                for msg_data in data.get('value', []):
                    email = await self._parse_microsoft_365_email(msg_data, provider)
                    emails.append(email)
                
                return emails
                
        except Exception as e:
            logger.error(f"Error getting Microsoft 365 emails: {str(e)}")
            raise
    
    async def _get_google_workspace_emails(self, provider: EmailProviderConfig,
                                          folder_path: str, limit: int,
                                          since: Optional[datetime]) -> List[EmailMessage]:
        """Get emails from Google Workspace"""
        try:
            token = await self._get_google_workspace_token(provider)
            headers = {
                'Authorization': f'Bearer {token}',
                'Content-Type': 'application/json'
            }
            
            # Build API URL
            api_url = f"{provider.api_endpoints['gmail_api_url']}/gmail/v1/users/me/messages"
            
            # Build query
            query_parts = []
            if folder_path != "INBOX":
                if folder_path == "SPAM":
                    query_parts.append("in:spam")
                elif folder_path == "TRASH":
                    query_parts.append("in:trash")
                else:
                    query_parts.append(f"in:{folder_path.lower()}")
            
            if since:
                query_parts.append(f"after:{int(since.timestamp())}")
            
            params = {
                'maxResults': limit,
                'q': ' '.join(query_parts) if query_parts else 'in:inbox'
            }
            
            # Get message list
            async with self.session.get(api_url, headers=headers, params=params) as response:
                if response.status != 200:
                    raise Exception(f"API request failed: {response.status}")
                
                data = await response.json()
                message_ids = [msg['id'] for msg in data.get('messages', [])]
            
            # Get full message details
            emails = []
            for msg_id in message_ids:
                msg_url = f"{api_url}/{msg_id}"
                async with self.session.get(msg_url, headers=headers) as response:
                    if response.status == 200:
                        msg_data = await response.json()
                        email = await self._parse_google_workspace_email(msg_data, provider)
                        emails.append(email)
            
            return emails
            
        except Exception as e:
            logger.error(f"Error getting Google Workspace emails: {str(e)}")
            raise
    
    async def _parse_microsoft_365_email(self, msg_data: Dict[str, Any],
                                        provider: EmailProviderConfig) -> EmailMessage:
        """Parse Microsoft 365 email data"""
        try:
            # Extract basic email information
            message_id = msg_data.get('id', '')
            subject = msg_data.get('subject', '')
            
            # Parse addresses
            from_address = self._extract_microsoft_address(msg_data.get('from', {}))
            to_addresses = [self._extract_microsoft_address(addr) 
                           for addr in msg_data.get('toRecipients', [])]
            cc_addresses = [self._extract_microsoft_address(addr) 
                           for addr in msg_data.get('ccRecipients', [])]
            bcc_addresses = [self._extract_microsoft_address(addr) 
                            for addr in msg_data.get('bccRecipients', [])]
            
            # Parse body
            body_data = msg_data.get('body', {})
            body_html = body_data.get('content', '') if body_data.get('contentType') == 'html' else None
            body_text = body_data.get('content', '') if body_data.get('contentType') == 'text' else None
            
            # Parse attachments
            attachments = []
            for att_data in msg_data.get('attachments', []):
                attachments.append({
                    'id': att_data.get('id', ''),
                    'name': att_data.get('name', ''),
                    'size': att_data.get('size', 0),
                    'content_type': att_data.get('contentType', '')
                })
            
            # Create metadata
            received_dt = datetime.fromisoformat(
                msg_data.get('receivedDateTime', '').replace('Z', '+00:00')
            )
            
            metadata = EmailMetadata(
                provider_message_id=message_id,
                provider_thread_id=msg_data.get('conversationId'),
                folder_path="INBOX",  # Would need to determine actual folder
                labels=[],
                is_read=msg_data.get('isRead', False),
                is_flagged=msg_data.get('flag', {}).get('flagStatus') == 'flagged',
                received_datetime=received_dt,
                size_bytes=0,  # Not provided in basic response
                has_attachments=msg_data.get('hasAttachments', False),
                importance=msg_data.get('importance', 'normal'),
                sensitivity='normal'  # Default
            )
            
            return EmailMessage(
                message_id=message_id,
                provider_metadata=metadata,
                from_address=from_address,
                to_addresses=to_addresses,
                cc_addresses=cc_addresses,
                bcc_addresses=bcc_addresses,
                subject=subject,
                body_text=body_text,
                body_html=body_html,
                attachments=attachments,
                headers={},  # Would need separate API call to get full headers
                raw_message=None
            )
            
        except Exception as e:
            logger.error(f"Error parsing Microsoft 365 email: {str(e)}")
            raise
    
    async def _parse_google_workspace_email(self, msg_data: Dict[str, Any],
                                           provider: EmailProviderConfig) -> EmailMessage:
        """Parse Google Workspace email data"""
        try:
            message_id = msg_data.get('id', '')
            thread_id = msg_data.get('threadId', '')
            
            # Parse headers
            headers = {}
            header_data = msg_data.get('payload', {}).get('headers', [])
            for header in header_data:
                headers[header['name']] = header['value']
            
            # Extract common headers
            subject = headers.get('Subject', '')
            from_address = headers.get('From', '')
            to_addresses = self._parse_address_list(headers.get('To', ''))
            cc_addresses = self._parse_address_list(headers.get('Cc', ''))
            bcc_addresses = self._parse_address_list(headers.get('Bcc', ''))
            
            # Parse body
            body_text, body_html = self._extract_gmail_body(msg_data.get('payload', {}))
            
            # Parse attachments
            attachments = self._extract_gmail_attachments(msg_data.get('payload', {}))
            
            # Parse labels and folder
            label_ids = msg_data.get('labelIds', [])
            folder_path = "INBOX" if "INBOX" in label_ids else "UNKNOWN"
            
            # Create metadata
            received_dt = datetime.fromtimestamp(
                int(msg_data.get('internalDate', '0')) / 1000,
                tz=timezone.utc
            )
            
            metadata = EmailMetadata(
                provider_message_id=message_id,
                provider_thread_id=thread_id,
                folder_path=folder_path,
                labels=label_ids,
                is_read="UNREAD" not in label_ids,
                is_flagged="STARRED" in label_ids,
                received_datetime=received_dt,
                size_bytes=msg_data.get('sizeEstimate', 0),
                has_attachments=len(attachments) > 0,
                importance='normal',  # Gmail doesn't have importance
                sensitivity='normal'
            )
            
            return EmailMessage(
                message_id=message_id,
                provider_metadata=metadata,
                from_address=from_address,
                to_addresses=to_addresses,
                cc_addresses=cc_addresses,
                bcc_addresses=bcc_addresses,
                subject=subject,
                body_text=body_text,
                body_html=body_html,
                attachments=attachments,
                headers=headers,
                raw_message=None
            )
            
        except Exception as e:
            logger.error(f"Error parsing Google Workspace email: {str(e)}")
            raise
    
    def _extract_microsoft_address(self, addr_data: Dict[str, Any]) -> str:
        """Extract email address from Microsoft 365 address object"""
        try:
            email_addr = addr_data.get('emailAddress', {})
            name = email_addr.get('name', '')
            address = email_addr.get('address', '')
            
            if name and name != address:
                return f"{name} <{address}>"
            else:
                return address
                
        except Exception:
            return ""
    
    def _parse_address_list(self, address_string: str) -> List[str]:
        """Parse comma-separated address list"""
        try:
            if not address_string:
                return []
            
            # Simple parsing - production would use proper email parser
            addresses = []
            for addr in address_string.split(','):
                addr = addr.strip()
                if addr:
                    addresses.append(addr)
            
            return addresses
            
        except Exception:
            return []
    
    def _extract_gmail_body(self, payload: Dict[str, Any]) -> Tuple[Optional[str], Optional[str]]:
        """Extract body text and HTML from Gmail payload"""
        try:
            body_text = None
            body_html = None
            
            # Check if message has parts (multipart)
            if 'parts' in payload:
                for part in payload['parts']:
                    mime_type = part.get('mimeType', '')
                    body_data = part.get('body', {})
                    
                    if mime_type == 'text/plain' and 'data' in body_data:
                        body_text = base64.urlsafe_b64decode(
                            body_data['data'] + '=='
                        ).decode('utf-8', errors='ignore')
                    elif mime_type == 'text/html' and 'data' in body_data:
                        body_html = base64.urlsafe_b64decode(
                            body_data['data'] + '=='
                        ).decode('utf-8', errors='ignore')
            
            # Single part message
            else:
                mime_type = payload.get('mimeType', '')
                body_data = payload.get('body', {})
                
                if 'data' in body_data:
                    content = base64.urlsafe_b64decode(
                        body_data['data'] + '=='
                    ).decode('utf-8', errors='ignore')
                    
                    if mime_type == 'text/plain':
                        body_text = content
                    elif mime_type == 'text/html':
                        body_html = content
            
            return body_text, body_html
            
        except Exception as e:
            logger.warning(f"Error extracting Gmail body: {str(e)}")
            return None, None
    
    def _extract_gmail_attachments(self, payload: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract attachment information from Gmail payload"""
        try:
            attachments = []
            
            def extract_parts(parts):
                for part in parts:
                    if part.get('filename'):
                        attachments.append({
                            'id': part.get('body', {}).get('attachmentId', ''),
                            'name': part.get('filename', ''),
                            'size': part.get('body', {}).get('size', 0),
                            'content_type': part.get('mimeType', '')
                        })
                    
                    # Recursively check nested parts
                    if 'parts' in part:
                        extract_parts(part['parts'])
            
            if 'parts' in payload:
                extract_parts(payload['parts'])
            
            return attachments
            
        except Exception as e:
            logger.warning(f"Error extracting Gmail attachments: {str(e)}")
            return []
    
    async def perform_email_action(self, provider_id: str, message_id: str,
                                  action: EmailAction, **kwargs) -> bool:
        """Perform action on email message"""
        try:
            provider = self.providers.get(provider_id)
            if not provider:
                raise ValueError(f"Provider not found: {provider_id}")
            
            # Check rate limits
            if not await self._check_rate_limit(provider_id, 'email_action'):
                raise Exception("Rate limit exceeded")
            
            # Perform action based on provider type
            if provider.provider_type == ProviderType.MICROSOFT_365:
                success = await self._perform_microsoft_365_action(
                    provider, message_id, action, **kwargs
                )
            elif provider.provider_type == ProviderType.GOOGLE_WORKSPACE:
                success = await self._perform_google_workspace_action(
                    provider, message_id, action, **kwargs
                )
            else:
                raise ValueError(f"Unsupported provider type: {provider.provider_type}")
            
            # Log action
            await self._log_email_action(provider_id, message_id, action, success)
            
            # Update health status
            await self._update_health_status(provider_id, success)
            
            return success
            
        except Exception as e:
            await self._update_health_status(provider_id, False, str(e))
            logger.error(f"Error performing email action: {str(e)}")
            return False
    
    async def _perform_microsoft_365_action(self, provider: EmailProviderConfig,
                                           message_id: str, action: EmailAction,
                                           **kwargs) -> bool:
        """Perform action on Microsoft 365 email"""
        try:
            token = await self._get_microsoft_365_token(provider)
            headers = {
                'Authorization': f'Bearer {token}',
                'Content-Type': 'application/json'
            }
            
            base_url = f"{provider.api_endpoints['graph_api_url']}/v1.0/me/messages/{message_id}"
            
            if action == EmailAction.DELETE:
                async with self.session.delete(base_url, headers=headers) as response:
                    return response.status == 204
            
            elif action == EmailAction.MARK_AS_READ:
                data = {'isRead': True}
                async with self.session.patch(base_url, headers=headers, json=data) as response:
                    return response.status == 200
            
            elif action == EmailAction.MOVE_TO_FOLDER:
                folder_id = kwargs.get('folder_id')
                if not folder_id:
                    return False
                
                data = {'destinationId': folder_id}
                async with self.session.post(f"{base_url}/move", headers=headers, json=data) as response:
                    return response.status == 201
            
            else:
                logger.warning(f"Unsupported action for Microsoft 365: {action}")
                return False
                
        except Exception as e:
            logger.error(f"Error performing Microsoft 365 action: {str(e)}")
            return False
    
    async def _perform_google_workspace_action(self, provider: EmailProviderConfig,
                                              message_id: str, action: EmailAction,
                                              **kwargs) -> bool:
        """Perform action on Google Workspace email"""
        try:
            token = await self._get_google_workspace_token(provider)
            headers = {
                'Authorization': f'Bearer {token}',
                'Content-Type': 'application/json'
            }
            
            base_url = f"{provider.api_endpoints['gmail_api_url']}/gmail/v1/users/me/messages/{message_id}"
            
            if action == EmailAction.DELETE:
                async with self.session.delete(base_url, headers=headers) as response:
                    return response.status == 204
            
            elif action == EmailAction.MARK_AS_READ:
                data = {'removeLabelIds': ['UNREAD']}
                async with self.session.post(f"{base_url}/modify", headers=headers, json=data) as response:
                    return response.status == 200
            
            elif action == EmailAction.ADD_LABEL:
                label_id = kwargs.get('label_id')
                if not label_id:
                    return False
                
                data = {'addLabelIds': [label_id]}
                async with self.session.post(f"{base_url}/modify", headers=headers, json=data) as response:
                    return response.status == 200
            
            elif action == EmailAction.MARK_AS_SPAM:
                data = {'addLabelIds': ['SPAM'], 'removeLabelIds': ['INBOX']}
                async with self.session.post(f"{base_url}/modify", headers=headers, json=data) as response:
                    return response.status == 200
            
            else:
                logger.warning(f"Unsupported action for Google Workspace: {action}")
                return False
                
        except Exception as e:
            logger.error(f"Error performing Google Workspace action: {str(e)}")
            return False
    
    async def bulk_email_operation(self, provider_id: str, message_ids: List[str],
                                  action: EmailAction, **kwargs) -> BulkOperationResult:
        """Perform bulk operation on multiple emails"""
        operation_id = str(uuid.uuid4())
        start_time = datetime.now(timezone.utc)
        
        try:
            provider = self.providers.get(provider_id)
            if not provider:
                raise ValueError(f"Provider not found: {provider_id}")
            
            total_messages = len(message_ids)
            processed_messages = 0
            successful_operations = 0
            failed_operations = 0
            errors = []
            
            # Process in batches
            batch_size = self.config.get('bulk_operation_batch_size', 100)
            
            for i in range(0, total_messages, batch_size):
                batch = message_ids[i:i + batch_size]
                
                # Process batch
                for message_id in batch:
                    try:
                        success = await self.perform_email_action(
                            provider_id, message_id, action, **kwargs
                        )
                        
                        processed_messages += 1
                        
                        if success:
                            successful_operations += 1
                        else:
                            failed_operations += 1
                            errors.append(f"Action failed for message {message_id}")
                    
                    except Exception as e:
                        processed_messages += 1
                        failed_operations += 1
                        errors.append(f"Error processing message {message_id}: {str(e)}")
                
                # Rate limiting between batches
                await asyncio.sleep(0.1)
            
            # Calculate duration
            processing_duration = (datetime.now(timezone.utc) - start_time).total_seconds()
            
            # Create result
            result = BulkOperationResult(
                operation_id=operation_id,
                total_messages=total_messages,
                processed_messages=processed_messages,
                successful_operations=successful_operations,
                failed_operations=failed_operations,
                errors=errors,
                processing_duration=processing_duration
            )
            
            # Store bulk operation result
            await self._store_bulk_operation_result(provider_id, result, action)
            
            logger.info(f"Bulk operation completed: {successful_operations}/{total_messages} successful")
            return result
            
        except Exception as e:
            processing_duration = (datetime.now(timezone.utc) - start_time).total_seconds()
            logger.error(f"Error in bulk email operation: {str(e)}")
            
            return BulkOperationResult(
                operation_id=operation_id,
                total_messages=len(message_ids),
                processed_messages=0,
                successful_operations=0,
                failed_operations=len(message_ids),
                errors=[str(e)],
                processing_duration=processing_duration
            )
    
    async def _get_microsoft_365_token(self, provider: EmailProviderConfig) -> Optional[str]:
        """Get Microsoft 365 access token"""
        try:
            # Check if current token is still valid
            if (provider.credentials.access_token and 
                provider.credentials.token_expires and
                datetime.now(timezone.utc) < provider.credentials.token_expires - 
                timedelta(minutes=self.config.get('token_refresh_buffer_minutes', 5))):
                return provider.credentials.access_token
            
            # Refresh token if available
            if provider.credentials.refresh_token:
                return await self._refresh_microsoft_365_token(provider)
            
            # Otherwise would need to initiate OAuth flow
            logger.error("No valid Microsoft 365 token available")
            return None
            
        except Exception as e:
            logger.error(f"Error getting Microsoft 365 token: {str(e)}")
            return None
    
    async def _refresh_microsoft_365_token(self, provider: EmailProviderConfig) -> Optional[str]:
        """Refresh Microsoft 365 access token"""
        try:
            token_url = provider.api_endpoints['token_url']
            
            data = {
                'grant_type': 'refresh_token',
                'refresh_token': provider.credentials.refresh_token,
                'client_id': provider.credentials.client_id,
                'client_secret': provider.credentials.client_secret,
            }
            
            async with self.session.post(token_url, data=data) as response:
                if response.status != 200:
                    logger.error(f"Token refresh failed: {response.status}")
                    return None
                
                token_data = await response.json()
                
                # Update credentials
                provider.credentials.access_token = token_data.get('access_token')
                provider.credentials.refresh_token = token_data.get('refresh_token', 
                                                                   provider.credentials.refresh_token)
                
                expires_in = token_data.get('expires_in', 3600)
                provider.credentials.token_expires = (
                    datetime.now(timezone.utc) + timedelta(seconds=expires_in)
                )
                
                # Update stored configuration
                await self._store_provider_config(provider)
                
                return provider.credentials.access_token
                
        except Exception as e:
            logger.error(f"Error refreshing Microsoft 365 token: {str(e)}")
            return None
    
    async def _get_google_workspace_token(self, provider: EmailProviderConfig) -> Optional[str]:
        """Get Google Workspace access token"""
        try:
            # Check if current token is still valid
            if (provider.credentials.access_token and 
                provider.credentials.token_expires and
                datetime.now(timezone.utc) < provider.credentials.token_expires - 
                timedelta(minutes=self.config.get('token_refresh_buffer_minutes', 5))):
                return provider.credentials.access_token
            
            # Refresh token if available
            if provider.credentials.refresh_token:
                return await self._refresh_google_workspace_token(provider)
            
            # Otherwise would need to initiate OAuth flow
            logger.error("No valid Google Workspace token available")
            return None
            
        except Exception as e:
            logger.error(f"Error getting Google Workspace token: {str(e)}")
            return None
    
    async def _refresh_google_workspace_token(self, provider: EmailProviderConfig) -> Optional[str]:
        """Refresh Google Workspace access token"""
        try:
            token_url = provider.api_endpoints['token_url']
            
            data = {
                'grant_type': 'refresh_token',
                'refresh_token': provider.credentials.refresh_token,
                'client_id': provider.credentials.client_id,
                'client_secret': provider.credentials.client_secret,
            }
            
            async with self.session.post(token_url, data=data) as response:
                if response.status != 200:
                    logger.error(f"Token refresh failed: {response.status}")
                    return None
                
                token_data = await response.json()
                
                # Update credentials
                provider.credentials.access_token = token_data.get('access_token')
                
                expires_in = token_data.get('expires_in', 3600)
                provider.credentials.token_expires = (
                    datetime.now(timezone.utc) + timedelta(seconds=expires_in)
                )
                
                # Update stored configuration
                await self._store_provider_config(provider)
                
                return provider.credentials.access_token
                
        except Exception as e:
            logger.error(f"Error refreshing Google Workspace token: {str(e)}")
            return None
    
    async def _check_rate_limit(self, provider_id: str, operation: str) -> bool:
        """Check if operation is within rate limits"""
        try:
            provider = self.providers.get(provider_id)
            if not provider:
                return False
            
            current_time = datetime.now(timezone.utc)
            
            # Get rate limit for operation
            rate_limit = provider.rate_limits.get(operation, 1000)  # Default 1000/hour
            
            # Check rate limiter
            if provider_id not in self.rate_limiters:
                self.rate_limiters[provider_id] = {}
            
            limiter_key = f"{operation}_requests"
            if limiter_key not in self.rate_limiters[provider_id]:
                self.rate_limiters[provider_id][limiter_key] = []
            
            # Clean old requests (older than 1 hour)
            cutoff_time = current_time - timedelta(hours=1)
            self.rate_limiters[provider_id][limiter_key] = [
                req_time for req_time in self.rate_limiters[provider_id][limiter_key]
                if req_time > cutoff_time
            ]
            
            # Check if within limit
            request_count = len(self.rate_limiters[provider_id][limiter_key])
            buffer_limit = int(rate_limit * (1 - self.config.get('rate_limit_buffer', 0.1)))
            
            if request_count >= buffer_limit:
                # Update health status
                self.health_status[provider_id].rate_limit_hits += 1
                return False
            
            # Add current request
            self.rate_limiters[provider_id][limiter_key].append(current_time)
            return True
            
        except Exception as e:
            logger.error(f"Error checking rate limit: {str(e)}")
            return False
    
    async def _update_health_status(self, provider_id: str, success: bool, error_msg: str = None):
        """Update provider health status"""
        try:
            if provider_id not in self.health_status:
                return
            
            health = self.health_status[provider_id]
            health.total_requests += 1
            
            if success:
                health.successful_requests += 1
                health.last_successful_request = datetime.now(timezone.utc)
                health.status = IntegrationStatus.CONNECTED
            else:
                health.failed_requests += 1
                if error_msg and "rate limit" in error_msg.lower():
                    health.status = IntegrationStatus.RATE_LIMITED
                else:
                    health.status = IntegrationStatus.ERROR
            
            # Calculate error rate
            if health.total_requests > 0:
                health.error_rate = health.failed_requests / health.total_requests
            
        except Exception as e:
            logger.error(f"Error updating health status: {str(e)}")
    
    async def _store_provider_config(self, provider: EmailProviderConfig):
        """Store provider configuration in database"""
        try:
            self.db_connection.execute('''
                INSERT OR REPLACE INTO providers
                (provider_id, provider_type, display_name, credentials, api_endpoints,
                 rate_limits, webhook_url, enabled, last_sync, created_timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                provider.provider_id,
                provider.provider_type.value,
                provider.display_name,
                json.dumps(asdict(provider.credentials)),
                json.dumps(provider.api_endpoints),
                json.dumps(provider.rate_limits),
                provider.webhook_url,
                provider.enabled,
                provider.last_sync.timestamp() if provider.last_sync else None,
                datetime.now().timestamp()
            ))
            
            self.db_connection.commit()
            
        except Exception as e:
            logger.error(f"Error storing provider config: {str(e)}")
    
    async def _log_email_action(self, provider_id: str, message_id: str, 
                               action: EmailAction, success: bool):
        """Log email action to database"""
        try:
            self.db_connection.execute('''
                INSERT INTO processed_messages
                (message_id, provider_id, provider_message_id, processed_timestamp,
                 folder_path, action_taken, processing_duration)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                str(uuid.uuid4()),
                provider_id,
                message_id,
                datetime.now().timestamp(),
                'unknown',
                f"{action.value}:{'success' if success else 'failed'}",
                0.0
            ))
            
            self.db_connection.commit()
            
        except Exception as e:
            logger.error(f"Error logging email action: {str(e)}")
    
    async def _store_bulk_operation_result(self, provider_id: str, 
                                          result: BulkOperationResult, 
                                          action: EmailAction):
        """Store bulk operation result"""
        try:
            self.db_connection.execute('''
                INSERT INTO bulk_operations
                (operation_id, provider_id, operation_type, total_messages,
                 processed_messages, successful_operations, failed_operations,
                 start_timestamp, completion_timestamp, errors)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                result.operation_id,
                provider_id,
                action.value,
                result.total_messages,
                result.processed_messages,
                result.successful_operations,
                result.failed_operations,
                (datetime.now(timezone.utc) - timedelta(seconds=result.processing_duration)).timestamp(),
                datetime.now().timestamp(),
                json.dumps(result.errors)
            ))
            
            self.db_connection.commit()
            
        except Exception as e:
            logger.error(f"Error storing bulk operation result: {str(e)}")
    
    def get_provider_health(self, provider_id: str) -> Optional[IntegrationHealth]:
        """Get provider health status"""
        return self.health_status.get(provider_id)
    
    def get_integration_statistics(self) -> Dict[str, Any]:
        """Get integration performance statistics"""
        try:
            total_providers = len(self.providers)
            connected_providers = sum(
                1 for health in self.health_status.values()
                if health.status == IntegrationStatus.CONNECTED
            )
            
            stats = {
                'total_providers': total_providers,
                'connected_providers': connected_providers,
                'total_messages_processed': self.integration_stats['total_messages_processed'],
                'total_api_calls': self.integration_stats['total_api_calls'],
                'total_errors': self.integration_stats['total_errors'],
                'provider_health': {
                    provider_id: {
                        'status': health.status.value,
                        'success_rate': (
                            health.successful_requests / max(health.total_requests, 1) * 100
                        ),
                        'error_rate': health.error_rate * 100,
                        'rate_limit_hits': health.rate_limit_hits
                    }
                    for provider_id, health in self.health_status.items()
                }
            }
            
            return stats
            
        except Exception as e:
            logger.error(f"Error getting integration statistics: {str(e)}")
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
    """Example usage of EmailProviderIntegration"""
    
    # Example Microsoft 365 configuration
    microsoft_config = EmailProviderConfig(
        provider_id="microsoft_365_primary",
        provider_type=ProviderType.MICROSOFT_365,
        display_name="Microsoft 365 - ISECTECH",
        credentials=OAuth2Credentials(
            client_id="your_client_id",
            client_secret="your_client_secret",
            tenant_id="your_tenant_id",
            access_token=None,
            refresh_token="your_refresh_token",
            token_expires=None,
            scopes=["https://graph.microsoft.com/Mail.Read", "https://graph.microsoft.com/Mail.ReadWrite"]
        ),
        api_endpoints={
            "auth_url": "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize",
            "token_url": "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
            "graph_api_url": "https://graph.microsoft.com"
        },
        rate_limits={
            "get_emails": 1000,
            "email_action": 500
        },
        webhook_url=None,
        enabled=True,
        last_sync=None
    )
    
    # Example Google Workspace configuration
    google_config = EmailProviderConfig(
        provider_id="google_workspace_primary",
        provider_type=ProviderType.GOOGLE_WORKSPACE,
        display_name="Google Workspace - ISECTECH",
        credentials=OAuth2Credentials(
            client_id="your_client_id",
            client_secret="your_client_secret",
            tenant_id=None,
            access_token=None,
            refresh_token="your_refresh_token",
            token_expires=None,
            scopes=["https://www.googleapis.com/auth/gmail.readonly", "https://www.googleapis.com/auth/gmail.modify"]
        ),
        api_endpoints={
            "auth_url": "https://accounts.google.com/o/oauth2/auth",
            "token_url": "https://oauth2.googleapis.com/token",
            "gmail_api_url": "https://gmail.googleapis.com"
        },
        rate_limits={
            "get_emails": 2500,
            "email_action": 1000
        },
        webhook_url=None,
        enabled=True,
        last_sync=None
    )
    
    try:
        async with EmailProviderIntegration() as integration:
            # Add providers (would fail without valid credentials)
            print("Adding email providers...")
            # await integration.add_provider(microsoft_config)
            # await integration.add_provider(google_config)
            
            # Example operations (commented out as they require valid setup)
            # emails = await integration.get_emails("microsoft_365_primary", limit=10)
            # print(f"Retrieved {len(emails)} emails")
            
            # success = await integration.perform_email_action(
            #     "microsoft_365_primary", "message_id", EmailAction.MARK_AS_READ
            # )
            
            # bulk_result = await integration.bulk_email_operation(
            #     "google_workspace_primary", ["msg1", "msg2"], EmailAction.ADD_LABEL, label_id="SPAM"
            # )
            
            # Get statistics
            stats = integration.get_integration_statistics()
            print(f"Integration Statistics:")
            for key, value in stats.items():
                if key != 'provider_health':
                    print(f"  {key}: {value}")
        
    except Exception as e:
        logger.error(f"Error in example: {str(e)}")


if __name__ == "__main__":
    asyncio.run(main())