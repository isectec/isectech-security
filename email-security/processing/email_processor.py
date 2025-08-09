"""
Email Processing Foundation for ISECTECH Email Security Integration

This module provides comprehensive email processing capabilities including:
- MIME parsing and email structure analysis
- Attachment extraction and metadata collection
- Email header analysis and routing logic
- Basic email gateway interface
- Production-grade error handling and logging

Author: ISECTECH Security Team
Version: 1.0.0
"""

import asyncio
import email
import hashlib
import logging
import mimetypes
import os
import re
import uuid
from datetime import datetime, timezone
from email import policy
from email.message import EmailMessage
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Union
import base64
import json
import sqlite3
from dataclasses import dataclass, asdict
from enum import Enum

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class EmailSeverity(Enum):
    """Email security severity levels"""
    CLEAN = "clean"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AttachmentType(Enum):
    """Attachment classification types"""
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    EXECUTABLE = "executable"
    ARCHIVE = "archive"
    DOCUMENT = "document"
    IMAGE = "image"
    UNKNOWN = "unknown"


@dataclass
class EmailAttachment:
    """Email attachment metadata and content"""
    filename: str
    content_type: str
    size: int
    hash_md5: str
    hash_sha256: str
    attachment_type: AttachmentType
    is_embedded: bool
    content_disposition: str
    content_id: Optional[str] = None
    extracted_path: Optional[str] = None
    scan_results: Dict[str, Any] = None
    risk_score: float = 0.0
    
    def __post_init__(self):
        if self.scan_results is None:
            self.scan_results = {}


@dataclass
class EmailHeader:
    """Parsed email header information"""
    message_id: str
    from_address: str
    to_addresses: List[str]
    cc_addresses: List[str]
    bcc_addresses: List[str]
    subject: str
    date: datetime
    return_path: Optional[str]
    reply_to: Optional[str]
    sender: Optional[str]
    received: List[str]
    authentication_results: Optional[str]
    dkim_signature: Optional[str]
    spf_result: Optional[str]
    dmarc_result: Optional[str]
    x_headers: Dict[str, str]
    
    def __post_init__(self):
        if self.x_headers is None:
            self.x_headers = {}


@dataclass
class EmailContent:
    """Email content analysis"""
    plain_text: Optional[str]
    html_content: Optional[str]
    urls: List[str]
    embedded_images: List[str]
    external_links: List[str]
    suspicious_patterns: List[str]
    language: Optional[str]
    encoding: str
    word_count: int
    char_count: int
    has_scripts: bool
    has_forms: bool
    
    def __post_init__(self):
        if self.urls is None:
            self.urls = []
        if self.embedded_images is None:
            self.embedded_images = []
        if self.external_links is None:
            self.external_links = []
        if self.suspicious_patterns is None:
            self.suspicious_patterns = []


@dataclass
class ProcessedEmail:
    """Complete processed email data structure"""
    email_id: str
    raw_message: bytes
    headers: EmailHeader
    content: EmailContent
    attachments: List[EmailAttachment]
    processing_timestamp: datetime
    processing_duration: float
    file_size: int
    structure_analysis: Dict[str, Any]
    security_flags: List[str]
    risk_score: float
    severity: EmailSeverity
    
    def __post_init__(self):
        if self.attachments is None:
            self.attachments = []
        if self.structure_analysis is None:
            self.structure_analysis = {}
        if self.security_flags is None:
            self.security_flags = []


class EmailProcessingEngine:
    """
    Advanced email processing engine for security analysis
    
    Provides comprehensive email parsing, analysis, and metadata extraction
    optimized for security use cases and threat detection.
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        """Initialize email processing engine"""
        self.config = config or self._get_default_config()
        self.temp_dir = Path(self.config.get('temp_directory', '/tmp/email_processing'))
        self.temp_dir.mkdir(parents=True, exist_ok=True)
        
        # URL extraction patterns
        self.url_patterns = [
            re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+', re.IGNORECASE),
            re.compile(r'www\.[^\s<>"{}|\\^`\[\]]+', re.IGNORECASE),
            re.compile(r'[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^\s<>"{}|\\^`\[\]]*)?', re.IGNORECASE),
        ]
        
        # Suspicious pattern detection
        self.suspicious_patterns = [
            re.compile(r'urgent.*action.*required', re.IGNORECASE),
            re.compile(r'verify.*account.*immediately', re.IGNORECASE),
            re.compile(r'suspended.*account', re.IGNORECASE),
            re.compile(r'click.*here.*now', re.IGNORECASE),
            re.compile(r'limited.*time.*offer', re.IGNORECASE),
            re.compile(r'congratulations.*winner', re.IGNORECASE),
            re.compile(r'invoice.*attached', re.IGNORECASE),
            re.compile(r'payment.*failed', re.IGNORECASE),
        ]
        
        # Dangerous file extensions
        self.dangerous_extensions = {
            '.exe', '.scr', '.bat', '.cmd', '.com', '.pif', '.vbs', '.js',
            '.jar', '.app', '.deb', '.pkg', '.dmg', '.iso', '.msi', '.docm',
            '.xlsm', '.pptm', '.dotm', '.xltm', '.potm', '.ppam', '.sldm',
            '.wsf', '.hta', '.ps1', '.ps2', '.psc1', '.psc2', '.msh', '.msh1',
            '.msh2', '.mshxml', '.msh1xml', '.msh2xml'
        }
        
        # Initialize database
        self._init_database()
        
        logger.info("Email Processing Engine initialized")
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration"""
        return {
            'temp_directory': '/tmp/email_processing',
            'max_file_size': 50 * 1024 * 1024,  # 50MB
            'max_attachments': 100,
            'extraction_timeout': 30,
            'enable_content_analysis': True,
            'enable_url_extraction': True,
            'enable_pattern_detection': True,
            'store_raw_email': True,
            'quarantine_suspicious': True
        }
    
    def _init_database(self):
        """Initialize SQLite database for email processing metadata"""
        db_path = self.temp_dir / 'email_processing.db'
        self.db_connection = sqlite3.connect(str(db_path), check_same_thread=False)
        
        self.db_connection.execute('''
            CREATE TABLE IF NOT EXISTS processed_emails (
                email_id TEXT PRIMARY KEY,
                message_id TEXT,
                from_address TEXT,
                subject TEXT,
                processing_timestamp REAL,
                file_size INTEGER,
                attachment_count INTEGER,
                risk_score REAL,
                severity TEXT,
                security_flags TEXT,
                raw_data BLOB
            )
        ''')
        
        self.db_connection.execute('''
            CREATE TABLE IF NOT EXISTS email_attachments (
                attachment_id TEXT PRIMARY KEY,
                email_id TEXT,
                filename TEXT,
                content_type TEXT,
                size INTEGER,
                hash_md5 TEXT,
                hash_sha256 TEXT,
                attachment_type TEXT,
                risk_score REAL,
                FOREIGN KEY (email_id) REFERENCES processed_emails (email_id)
            )
        ''')
        
        self.db_connection.commit()
    
    async def process_email(self, email_data: Union[str, bytes, EmailMessage]) -> ProcessedEmail:
        """
        Process email message and extract all relevant security metadata
        
        Args:
            email_data: Raw email data (string, bytes, or EmailMessage)
            
        Returns:
            ProcessedEmail: Comprehensive processed email data
        """
        start_time = datetime.now(timezone.utc)
        email_id = str(uuid.uuid4())
        
        try:
            # Parse email message
            if isinstance(email_data, str):
                raw_bytes = email_data.encode('utf-8')
                message = email.message_from_string(email_data, policy=policy.default)
            elif isinstance(email_data, bytes):
                raw_bytes = email_data
                message = email.message_from_bytes(email_data, policy=policy.default)
            elif isinstance(email_data, EmailMessage):
                raw_bytes = str(email_data).encode('utf-8')
                message = email_data
            else:
                raise ValueError(f"Unsupported email data type: {type(email_data)}")
            
            # Extract headers
            headers = await self._extract_headers(message)
            
            # Extract content
            content = await self._extract_content(message)
            
            # Extract attachments
            attachments = await self._extract_attachments(message, email_id)
            
            # Analyze email structure
            structure_analysis = await self._analyze_structure(message)
            
            # Calculate risk score and severity
            risk_score, security_flags = await self._calculate_risk_score(
                headers, content, attachments, structure_analysis
            )
            severity = self._determine_severity(risk_score)
            
            # Create processed email object
            processed_email = ProcessedEmail(
                email_id=email_id,
                raw_message=raw_bytes,
                headers=headers,
                content=content,
                attachments=attachments,
                processing_timestamp=start_time,
                processing_duration=(datetime.now(timezone.utc) - start_time).total_seconds(),
                file_size=len(raw_bytes),
                structure_analysis=structure_analysis,
                security_flags=security_flags,
                risk_score=risk_score,
                severity=severity
            )
            
            # Store in database
            await self._store_processed_email(processed_email)
            
            logger.info(f"Successfully processed email {email_id} with risk score {risk_score}")
            return processed_email
            
        except Exception as e:
            logger.error(f"Error processing email {email_id}: {str(e)}")
            raise
    
    async def _extract_headers(self, message: EmailMessage) -> EmailHeader:
        """Extract and parse email headers"""
        try:
            # Parse addresses safely
            def parse_addresses(addr_str: Optional[str]) -> List[str]:
                if not addr_str:
                    return []
                try:
                    addresses = email.utils.getaddresses([addr_str])
                    return [addr[1] for addr in addresses if addr[1]]
                except Exception:
                    return [addr_str] if addr_str else []
            
            # Parse date safely
            date_str = message.get('Date')
            try:
                date = email.utils.parsedate_to_datetime(date_str) if date_str else datetime.now(timezone.utc)
            except Exception:
                date = datetime.now(timezone.utc)
            
            # Extract authentication headers
            x_headers = {}
            for key, value in message.items():
                if key.lower().startswith('x-'):
                    x_headers[key] = value
            
            return EmailHeader(
                message_id=message.get('Message-ID', f"<generated-{uuid.uuid4()}@isectech.local>"),
                from_address=message.get('From', ''),
                to_addresses=parse_addresses(message.get('To')),
                cc_addresses=parse_addresses(message.get('Cc')),
                bcc_addresses=parse_addresses(message.get('Bcc')),
                subject=message.get('Subject', ''),
                date=date,
                return_path=message.get('Return-Path'),
                reply_to=message.get('Reply-To'),
                sender=message.get('Sender'),
                received=message.get_all('Received', []),
                authentication_results=message.get('Authentication-Results'),
                dkim_signature=message.get('DKIM-Signature'),
                spf_result=message.get('Received-SPF'),
                dmarc_result=message.get('DMARC-Filter'),
                x_headers=x_headers
            )
            
        except Exception as e:
            logger.error(f"Error extracting headers: {str(e)}")
            raise
    
    async def _extract_content(self, message: EmailMessage) -> EmailContent:
        """Extract and analyze email content"""
        try:
            plain_text = None
            html_content = None
            urls = []
            embedded_images = []
            external_links = []
            suspicious_patterns = []
            
            # Extract text content
            if message.is_multipart():
                for part in message.walk():
                    content_type = part.get_content_type()
                    if content_type == 'text/plain' and not plain_text:
                        plain_text = part.get_content()
                    elif content_type == 'text/html' and not html_content:
                        html_content = part.get_content()
            else:
                content_type = message.get_content_type()
                content = message.get_content()
                if content_type == 'text/plain':
                    plain_text = content
                elif content_type == 'text/html':
                    html_content = content
                else:
                    plain_text = str(content)
            
            # Analyze content
            all_text = (plain_text or '') + (html_content or '')
            
            # Extract URLs
            if self.config.get('enable_url_extraction', True):
                for pattern in self.url_patterns:
                    urls.extend(pattern.findall(all_text))
                urls = list(set(urls))  # Remove duplicates
                
                # Classify URLs
                for url in urls:
                    if url.startswith(('http://', 'https://')):
                        external_links.append(url)
                    elif 'cid:' in url or 'data:image' in url:
                        embedded_images.append(url)
                    else:
                        external_links.append(url)
            
            # Detect suspicious patterns
            if self.config.get('enable_pattern_detection', True):
                for pattern in self.suspicious_patterns:
                    matches = pattern.findall(all_text)
                    suspicious_patterns.extend(matches)
            
            # Check for scripts and forms in HTML
            has_scripts = bool(html_content and re.search(r'<script[^>]*>', html_content, re.IGNORECASE))
            has_forms = bool(html_content and re.search(r'<form[^>]*>', html_content, re.IGNORECASE))
            
            return EmailContent(
                plain_text=plain_text,
                html_content=html_content,
                urls=urls,
                embedded_images=embedded_images,
                external_links=external_links,
                suspicious_patterns=suspicious_patterns,
                language=None,  # Could implement language detection
                encoding=message.get_charset() or 'utf-8',
                word_count=len(all_text.split()) if all_text else 0,
                char_count=len(all_text) if all_text else 0,
                has_scripts=has_scripts,
                has_forms=has_forms
            )
            
        except Exception as e:
            logger.error(f"Error extracting content: {str(e)}")
            raise
    
    async def _extract_attachments(self, message: EmailMessage, email_id: str) -> List[EmailAttachment]:
        """Extract and analyze email attachments"""
        attachments = []
        
        try:
            if not message.is_multipart():
                return attachments
            
            attachment_count = 0
            for part in message.walk():
                # Skip multipart containers and text parts
                if part.get_content_maintype() == 'multipart':
                    continue
                if part.get_content_type() in ['text/plain', 'text/html']:
                    continue
                
                # Check attachment limits
                if attachment_count >= self.config.get('max_attachments', 100):
                    logger.warning(f"Attachment limit reached for email {email_id}")
                    break
                
                # Get attachment metadata
                filename = part.get_filename()
                if not filename:
                    # Generate filename for unnamed attachments
                    ext = mimetypes.guess_extension(part.get_content_type()) or '.bin'
                    filename = f"attachment_{attachment_count}{ext}"
                
                # Get content disposition
                content_disposition = part.get('Content-Disposition', '')
                is_embedded = 'inline' in content_disposition.lower()
                content_id = part.get('Content-ID')
                
                # Extract content
                try:
                    content = part.get_content()
                    if isinstance(content, str):
                        content = content.encode('utf-8')
                    elif not isinstance(content, bytes):
                        content = str(content).encode('utf-8')
                except Exception as e:
                    logger.warning(f"Could not extract content for attachment {filename}: {str(e)}")
                    continue
                
                # Check file size limits
                if len(content) > self.config.get('max_file_size', 50 * 1024 * 1024):
                    logger.warning(f"Attachment {filename} exceeds size limit")
                    continue
                
                # Calculate hashes
                md5_hash = hashlib.md5(content).hexdigest()
                sha256_hash = hashlib.sha256(content).hexdigest()
                
                # Classify attachment type
                attachment_type = self._classify_attachment(filename, part.get_content_type(), content)
                
                # Save attachment to temporary directory
                extracted_path = None
                if self.config.get('store_attachments', True):
                    safe_filename = re.sub(r'[^\w\-_\.]', '_', filename)
                    extracted_path = self.temp_dir / f"{email_id}_{attachment_count}_{safe_filename}"
                    try:
                        with open(extracted_path, 'wb') as f:
                            f.write(content)
                    except Exception as e:
                        logger.warning(f"Could not save attachment {filename}: {str(e)}")
                        extracted_path = None
                
                # Calculate risk score for attachment
                risk_score = self._calculate_attachment_risk(filename, part.get_content_type(), len(content))
                
                attachment = EmailAttachment(
                    filename=filename,
                    content_type=part.get_content_type(),
                    size=len(content),
                    hash_md5=md5_hash,
                    hash_sha256=sha256_hash,
                    attachment_type=attachment_type,
                    is_embedded=is_embedded,
                    content_disposition=content_disposition,
                    content_id=content_id,
                    extracted_path=str(extracted_path) if extracted_path else None,
                    risk_score=risk_score
                )
                
                attachments.append(attachment)
                attachment_count += 1
            
            logger.info(f"Extracted {len(attachments)} attachments from email {email_id}")
            return attachments
            
        except Exception as e:
            logger.error(f"Error extracting attachments: {str(e)}")
            return attachments
    
    def _classify_attachment(self, filename: str, content_type: str, content: bytes) -> AttachmentType:
        """Classify attachment type based on filename, content type, and content"""
        try:
            # Get file extension
            ext = Path(filename).suffix.lower()
            
            # Check for dangerous executables
            if ext in self.dangerous_extensions:
                return AttachmentType.MALICIOUS if ext in {'.exe', '.scr', '.bat', '.cmd'} else AttachmentType.EXECUTABLE
            
            # Check content type
            if content_type.startswith('application/'):
                if 'executable' in content_type or 'octet-stream' in content_type:
                    return AttachmentType.SUSPICIOUS
                elif content_type in ['application/zip', 'application/x-rar', 'application/x-7z-compressed']:
                    return AttachmentType.ARCHIVE
                elif 'office' in content_type or content_type.startswith('application/vnd.'):
                    return AttachmentType.DOCUMENT
            elif content_type.startswith('image/'):
                return AttachmentType.IMAGE
            
            # Check for suspicious patterns in content (first 1KB)
            try:
                sample = content[:1024].decode('utf-8', errors='ignore').lower()
                if any(keyword in sample for keyword in ['payload', 'shellcode', 'exploit', 'malware']):
                    return AttachmentType.SUSPICIOUS
            except Exception:
                pass
            
            # Default classification
            safe_extensions = {'.txt', '.pdf', '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.docx', '.xlsx', '.pptx'}
            return AttachmentType.SAFE if ext in safe_extensions else AttachmentType.UNKNOWN
            
        except Exception as e:
            logger.warning(f"Error classifying attachment {filename}: {str(e)}")
            return AttachmentType.UNKNOWN
    
    def _calculate_attachment_risk(self, filename: str, content_type: str, size: int) -> float:
        """Calculate risk score for attachment (0.0 - 10.0)"""
        risk_score = 0.0
        
        try:
            ext = Path(filename).suffix.lower()
            
            # Executable files are high risk
            if ext in self.dangerous_extensions:
                risk_score += 8.0
            
            # Suspicious content types
            if 'executable' in content_type or 'octet-stream' in content_type:
                risk_score += 6.0
            
            # Compressed files can hide malware
            if ext in {'.zip', '.rar', '.7z', '.tar', '.gz'}:
                risk_score += 3.0
            
            # Very large files are suspicious
            if size > 10 * 1024 * 1024:  # > 10MB
                risk_score += 2.0
            elif size > 100 * 1024 * 1024:  # > 100MB
                risk_score += 4.0
            
            # Suspicious filename patterns
            suspicious_patterns = ['invoice', 'receipt', 'document', 'important', 'urgent', 'payment']
            if any(pattern in filename.lower() for pattern in suspicious_patterns):
                risk_score += 2.0
            
            # Double extensions are suspicious
            if filename.count('.') > 1:
                risk_score += 3.0
            
            return min(risk_score, 10.0)
            
        except Exception as e:
            logger.warning(f"Error calculating attachment risk for {filename}: {str(e)}")
            return 5.0  # Default medium risk
    
    async def _analyze_structure(self, message: EmailMessage) -> Dict[str, Any]:
        """Analyze email structure for security assessment"""
        try:
            structure = {
                'is_multipart': message.is_multipart(),
                'part_count': 0,
                'has_attachments': False,
                'has_inline_content': False,
                'has_html': False,
                'has_plain_text': False,
                'content_types': [],
                'encoding_issues': [],
                'header_count': len(message.items()),
                'received_hops': len(message.get_all('Received', [])),
                'suspicious_headers': []
            }
            
            if message.is_multipart():
                for part in message.walk():
                    structure['part_count'] += 1
                    content_type = part.get_content_type()
                    structure['content_types'].append(content_type)
                    
                    if content_type == 'text/html':
                        structure['has_html'] = True
                    elif content_type == 'text/plain':
                        structure['has_plain_text'] = True
                    elif part.get_filename():
                        structure['has_attachments'] = True
                    elif part.get('Content-Disposition', '').startswith('inline'):
                        structure['has_inline_content'] = True
                    
                    # Check for encoding issues
                    try:
                        part.get_content()
                    except Exception as e:
                        structure['encoding_issues'].append(str(e))
            else:
                structure['part_count'] = 1
                structure['content_types'] = [message.get_content_type()]
                if message.get_content_type() == 'text/html':
                    structure['has_html'] = True
                elif message.get_content_type() == 'text/plain':
                    structure['has_plain_text'] = True
            
            # Check for suspicious headers
            suspicious_header_patterns = [
                'x-mailer-daemon',
                'x-spam',
                'x-virus',
                'x-phishing'
            ]
            
            for header_name, header_value in message.items():
                if any(pattern in header_name.lower() for pattern in suspicious_header_patterns):
                    structure['suspicious_headers'].append(f"{header_name}: {header_value}")
            
            return structure
            
        except Exception as e:
            logger.error(f"Error analyzing email structure: {str(e)}")
            return {'error': str(e)}
    
    async def _calculate_risk_score(self, headers: EmailHeader, content: EmailContent, 
                                   attachments: List[EmailAttachment], structure: Dict[str, Any]) -> Tuple[float, List[str]]:
        """Calculate overall email risk score and security flags"""
        risk_score = 0.0
        security_flags = []
        
        try:
            # Header-based risk factors
            if not headers.from_address:
                risk_score += 2.0
                security_flags.append("missing_sender")
            
            if len(headers.received) < 2:
                risk_score += 1.5
                security_flags.append("suspicious_routing")
            
            if not headers.dkim_signature and not headers.spf_result:
                risk_score += 2.0
                security_flags.append("missing_authentication")
            
            # Content-based risk factors
            if content.suspicious_patterns:
                risk_score += len(content.suspicious_patterns) * 1.5
                security_flags.append("suspicious_content")
            
            if content.has_scripts:
                risk_score += 3.0
                security_flags.append("embedded_scripts")
            
            if content.has_forms:
                risk_score += 2.0
                security_flags.append("embedded_forms")
            
            if len(content.external_links) > 10:
                risk_score += 2.0
                security_flags.append("excessive_links")
            
            # Attachment-based risk factors
            high_risk_attachments = [att for att in attachments if att.risk_score > 7.0]
            if high_risk_attachments:
                risk_score += len(high_risk_attachments) * 3.0
                security_flags.append("high_risk_attachments")
            
            executable_attachments = [att for att in attachments if att.attachment_type == AttachmentType.EXECUTABLE]
            if executable_attachments:
                risk_score += len(executable_attachments) * 4.0
                security_flags.append("executable_attachments")
            
            # Structure-based risk factors
            if structure.get('encoding_issues'):
                risk_score += 1.0
                security_flags.append("encoding_issues")
            
            if structure.get('suspicious_headers'):
                risk_score += len(structure['suspicious_headers']) * 1.0
                security_flags.append("suspicious_headers")
            
            # Normalize risk score to 0-10 range
            risk_score = min(risk_score, 10.0)
            
            return risk_score, security_flags
            
        except Exception as e:
            logger.error(f"Error calculating risk score: {str(e)}")
            return 5.0, ["calculation_error"]
    
    def _determine_severity(self, risk_score: float) -> EmailSeverity:
        """Determine email severity based on risk score"""
        if risk_score >= 8.0:
            return EmailSeverity.CRITICAL
        elif risk_score >= 6.0:
            return EmailSeverity.HIGH
        elif risk_score >= 4.0:
            return EmailSeverity.MEDIUM
        elif risk_score >= 2.0:
            return EmailSeverity.LOW
        else:
            return EmailSeverity.CLEAN
    
    async def _store_processed_email(self, processed_email: ProcessedEmail):
        """Store processed email metadata in database"""
        try:
            # Store main email record
            self.db_connection.execute('''
                INSERT OR REPLACE INTO processed_emails 
                (email_id, message_id, from_address, subject, processing_timestamp, 
                 file_size, attachment_count, risk_score, severity, security_flags, raw_data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                processed_email.email_id,
                processed_email.headers.message_id,
                processed_email.headers.from_address,
                processed_email.headers.subject,
                processed_email.processing_timestamp.timestamp(),
                processed_email.file_size,
                len(processed_email.attachments),
                processed_email.risk_score,
                processed_email.severity.value,
                json.dumps(processed_email.security_flags),
                processed_email.raw_message if self.config.get('store_raw_email', True) else None
            ))
            
            # Store attachment records
            for attachment in processed_email.attachments:
                self.db_connection.execute('''
                    INSERT OR REPLACE INTO email_attachments
                    (attachment_id, email_id, filename, content_type, size, 
                     hash_md5, hash_sha256, attachment_type, risk_score)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    f"{processed_email.email_id}_{attachment.filename}",
                    processed_email.email_id,
                    attachment.filename,
                    attachment.content_type,
                    attachment.size,
                    attachment.hash_md5,
                    attachment.hash_sha256,
                    attachment.attachment_type.value,
                    attachment.risk_score
                ))
            
            self.db_connection.commit()
            logger.debug(f"Stored processed email {processed_email.email_id} in database")
            
        except Exception as e:
            logger.error(f"Error storing processed email: {str(e)}")
            raise
    
    async def get_processed_email(self, email_id: str) -> Optional[ProcessedEmail]:
        """Retrieve processed email from database"""
        try:
            cursor = self.db_connection.execute('''
                SELECT * FROM processed_emails WHERE email_id = ?
            ''', (email_id,))
            
            row = cursor.fetchone()
            if not row:
                return None
            
            # Note: This is a simplified retrieval - full reconstruction would require
            # deserializing all the complex data structures
            logger.info(f"Retrieved processed email {email_id} from database")
            return None  # Placeholder - would implement full deserialization
            
        except Exception as e:
            logger.error(f"Error retrieving processed email {email_id}: {str(e)}")
            return None
    
    async def cleanup_temp_files(self, older_than_hours: int = 24):
        """Clean up temporary files older than specified hours"""
        try:
            cutoff_time = datetime.now() - datetime.timedelta(hours=older_than_hours)
            deleted_count = 0
            
            for file_path in self.temp_dir.iterdir():
                if file_path.is_file() and datetime.fromtimestamp(file_path.stat().st_mtime) < cutoff_time:
                    try:
                        file_path.unlink()
                        deleted_count += 1
                    except Exception as e:
                        logger.warning(f"Could not delete temp file {file_path}: {str(e)}")
            
            logger.info(f"Cleaned up {deleted_count} temporary files")
            
        except Exception as e:
            logger.error(f"Error during temp file cleanup: {str(e)}")
    
    def __del__(self):
        """Cleanup database connection"""
        try:
            if hasattr(self, 'db_connection'):
                self.db_connection.close()
        except Exception:
            pass


# Example usage and testing
async def main():
    """Example usage of EmailProcessingEngine"""
    engine = EmailProcessingEngine()
    
    # Example email for testing
    test_email = """From: sender@example.com
To: recipient@isectech.com
Subject: Test Email with Attachment
Date: Mon, 1 Jan 2024 12:00:00 +0000
Message-ID: <test@example.com>
Content-Type: multipart/mixed; boundary="boundary123"

--boundary123
Content-Type: text/plain

This is a test email with suspicious content.
Click here to verify your account immediately!
Urgent action required.

--boundary123
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="suspicious.exe"
Content-Transfer-Encoding: base64

VGhpcyBpcyBhIGZha2UgZXhlY3V0YWJsZSBmb3IgdGVzdGluZw==

--boundary123--
"""
    
    try:
        # Process the test email
        processed = await engine.process_email(test_email)
        
        print(f"Processed Email ID: {processed.email_id}")
        print(f"Risk Score: {processed.risk_score}")
        print(f"Severity: {processed.severity.value}")
        print(f"Security Flags: {processed.security_flags}")
        print(f"Attachments: {len(processed.attachments)}")
        
        if processed.attachments:
            for att in processed.attachments:
                print(f"  - {att.filename} ({att.attachment_type.value}, risk: {att.risk_score})")
        
    except Exception as e:
        logger.error(f"Error in example: {str(e)}")
    
    finally:
        # Cleanup
        await engine.cleanup_temp_files()


if __name__ == "__main__":
    asyncio.run(main())