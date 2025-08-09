"""
Identity Event Collection and Processing System
Production-grade event collection, validation, and processing for ISECTECH platform
Author: ISECTECH Security Team
Version: 1.0.0
"""

import asyncio
import json
import logging
import time
from typing import Dict, List, Optional, Any, Union, Callable, Set, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime, timezone, timedelta
from enum import Enum
import hashlib
import sqlite3
import aiosqlite
import uuid
import geoip2.database
from kafka import KafkaProducer, KafkaConsumer
from kafka.errors import KafkaError
import redis.asyncio as redis
import aiofiles
import xml.etree.ElementTree as ET
from cryptography.fernet import Fernet
import base64
from concurrent.futures import ThreadPoolExecutor
import threading
from queue import Queue, Empty
import socket
import struct


class EventType(Enum):
    """Identity event types for ISECTECH platform"""
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    LOGOUT = "logout"
    PASSWORD_CHANGE = "password_change"
    PASSWORD_RESET = "password_reset"
    ACCOUNT_LOCKED = "account_locked"
    ACCOUNT_UNLOCKED = "account_unlocked"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    PRIVILEGE_REVOKED = "privilege_revoked"
    RESOURCE_ACCESS = "resource_access"
    RESOURCE_ACCESS_DENIED = "resource_access_denied"
    MFA_SUCCESS = "mfa_success"
    MFA_FAILURE = "mfa_failure"
    SESSION_TIMEOUT = "session_timeout"
    SESSION_HIJACK_DETECTED = "session_hijack_detected"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    DATA_EXPORT = "data_export"
    DATA_MODIFICATION = "data_modification"
    POLICY_VIOLATION = "policy_violation"
    ADMIN_ACTION = "admin_action"


class EventSeverity(Enum):
    """Event severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ProtocolType(Enum):
    """Supported authentication protocols"""
    SAML = "saml"
    OIDC = "oidc"
    OAUTH2 = "oauth2"
    LDAP = "ldap"
    KERBEROS = "kerberos"
    RADIUS = "radius"
    NTLM = "ntlm"
    CUSTOM = "custom"


@dataclass
class GeoLocation:
    """Geographic location information"""
    country: Optional[str] = None
    country_code: Optional[str] = None
    city: Optional[str] = None
    region: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    timezone: Optional[str] = None
    isp: Optional[str] = None
    organization: Optional[str] = None
    asn: Optional[str] = None


@dataclass
class DeviceInfo:
    """Device and client information"""
    device_id: Optional[str] = None
    device_type: Optional[str] = None
    os: Optional[str] = None
    os_version: Optional[str] = None
    browser: Optional[str] = None
    browser_version: Optional[str] = None
    user_agent: Optional[str] = None
    screen_resolution: Optional[str] = None
    is_mobile: bool = False
    is_trusted: bool = False


@dataclass
class NetworkInfo:
    """Network connection information"""
    source_ip: str
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    vpn_detected: bool = False
    proxy_detected: bool = False
    tor_detected: bool = False


@dataclass
class SessionInfo:
    """Session-related information"""
    session_id: str
    session_start: Optional[datetime] = None
    session_duration: Optional[int] = None  # seconds
    concurrent_sessions: int = 1
    session_token_hash: Optional[str] = None
    idle_time: Optional[int] = None  # seconds


@dataclass
class IdentityEvent:
    """Core identity event structure for ISECTECH"""
    event_id: str
    timestamp: datetime
    event_type: EventType
    severity: EventSeverity
    user_id: str
    username: Optional[str] = None
    email: Optional[str] = None
    application: Optional[str] = None
    resource: Optional[str] = None
    action: Optional[str] = None
    result: Optional[str] = None
    message: Optional[str] = None
    protocol: Optional[ProtocolType] = None
    source_system: Optional[str] = None
    correlation_id: Optional[str] = None
    risk_score: float = 0.0
    
    # Extended information
    network_info: Optional[NetworkInfo] = None
    device_info: Optional[DeviceInfo] = None
    session_info: Optional[SessionInfo] = None
    geo_location: Optional[GeoLocation] = None
    
    # Context and metadata
    context: Optional[Dict[str, Any]] = None
    raw_data: Optional[Dict[str, Any]] = None
    tags: Optional[List[str]] = None
    
    # Processing metadata
    processed_at: Optional[datetime] = None
    processing_time_ms: Optional[float] = None
    validation_errors: Optional[List[str]] = None
    enrichment_status: Optional[str] = None


class EventValidator:
    """Event validation and sanitization"""
    
    def __init__(self):
        self.required_fields = {'event_id', 'timestamp', 'event_type', 'user_id'}
        self.max_string_length = 4096
        self.max_context_size = 32768
        
    def validate_event(self, event: IdentityEvent) -> Tuple[bool, List[str]]:
        """Validate event structure and content"""
        errors = []
        
        # Check required fields
        for field in self.required_fields:
            if not hasattr(event, field) or getattr(event, field) is None:
                errors.append(f"Missing required field: {field}")
        
        # Validate event_id format
        if event.event_id and not self._is_valid_uuid(event.event_id):
            errors.append("Invalid event_id format (must be UUID)")
        
        # Validate timestamp
        if event.timestamp and not isinstance(event.timestamp, datetime):
            errors.append("Invalid timestamp format")
        
        # Validate user_id
        if event.user_id and len(event.user_id) > 256:
            errors.append("user_id exceeds maximum length")
        
        # Validate string fields
        string_fields = ['username', 'email', 'application', 'resource', 'action', 'message']
        for field in string_fields:
            value = getattr(event, field, None)
            if value and len(str(value)) > self.max_string_length:
                errors.append(f"{field} exceeds maximum length")
        
        # Validate context size
        if event.context and len(json.dumps(event.context)) > self.max_context_size:
            errors.append("context exceeds maximum size")
        
        # Validate IP addresses
        if event.network_info and event.network_info.source_ip:
            if not self._is_valid_ip(event.network_info.source_ip):
                errors.append("Invalid source IP address")
        
        # Validate email format
        if event.email and not self._is_valid_email(event.email):
            errors.append("Invalid email format")
        
        return len(errors) == 0, errors
    
    def sanitize_event(self, event: IdentityEvent) -> IdentityEvent:
        """Sanitize event data"""
        # Truncate long strings
        if event.message and len(event.message) > self.max_string_length:
            event.message = event.message[:self.max_string_length] + "..."
            
        # Remove potentially dangerous characters
        if event.username:
            event.username = self._sanitize_string(event.username)
            
        if event.email:
            event.email = self._sanitize_string(event.email)
            
        # Ensure timezone info
        if event.timestamp and event.timestamp.tzinfo is None:
            event.timestamp = event.timestamp.replace(tzinfo=timezone.utc)
            
        return event
    
    def _is_valid_uuid(self, value: str) -> bool:
        """Check if string is valid UUID"""
        try:
            uuid.UUID(value)
            return True
        except ValueError:
            return False
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Check if string is valid IP address"""
        try:
            socket.inet_aton(ip)
            return True
        except socket.error:
            try:
                socket.inet_pton(socket.AF_INET6, ip)
                return True
            except socket.error:
                return False
    
    def _is_valid_email(self, email: str) -> bool:
        """Basic email validation"""
        return "@" in email and "." in email.split("@")[1]
    
    def _sanitize_string(self, value: str) -> str:
        """Remove potentially dangerous characters"""
        dangerous_chars = ['<', '>', '"', "'", '&', '\x00', '\r', '\n']
        for char in dangerous_chars:
            value = value.replace(char, '')
        return value.strip()


class EventEnricher:
    """Event enrichment with additional context"""
    
    def __init__(self, geoip_db_path: Optional[str] = None):
        self.geoip_reader = None
        if geoip_db_path:
            try:
                self.geoip_reader = geoip2.database.Reader(geoip_db_path)
            except Exception as e:
                logging.warning(f"Failed to load GeoIP database: {e}")
    
    async def enrich_event(self, event: IdentityEvent) -> IdentityEvent:
        """Enrich event with additional context"""
        enrichment_start = time.time()
        
        try:
            # Geo-location enrichment
            if event.network_info and event.network_info.source_ip:
                event.geo_location = await self._enrich_geolocation(event.network_info.source_ip)
            
            # Device fingerprinting
            if event.device_info and event.device_info.user_agent:
                event.device_info = await self._enrich_device_info(event.device_info)
            
            # Risk scoring (basic)
            event.risk_score = await self._calculate_basic_risk_score(event)
            
            # Add correlation ID if missing
            if not event.correlation_id:
                event.correlation_id = self._generate_correlation_id(event)
            
            # Set enrichment status
            event.enrichment_status = "completed"
            
        except Exception as e:
            logging.error(f"Event enrichment failed: {e}")
            event.enrichment_status = f"failed: {str(e)}"
        
        # Record processing time
        event.processing_time_ms = (time.time() - enrichment_start) * 1000
        
        return event
    
    async def _enrich_geolocation(self, ip_address: str) -> Optional[GeoLocation]:
        """Enrich with geolocation data"""
        if not self.geoip_reader:
            return None
        
        try:
            response = self.geoip_reader.city(ip_address)
            return GeoLocation(
                country=response.country.name,
                country_code=response.country.iso_code,
                city=response.city.name,
                region=response.subdivisions.most_specific.name,
                latitude=float(response.location.latitude) if response.location.latitude else None,
                longitude=float(response.location.longitude) if response.location.longitude else None,
                timezone=response.location.time_zone,
                isp=response.traits.isp if hasattr(response.traits, 'isp') else None,
                organization=response.traits.organization if hasattr(response.traits, 'organization') else None,
                asn=str(response.traits.autonomous_system_number) if hasattr(response.traits, 'autonomous_system_number') else None
            )
        except Exception as e:
            logging.warning(f"Geolocation enrichment failed for {ip_address}: {e}")
            return None
    
    async def _enrich_device_info(self, device_info: DeviceInfo) -> DeviceInfo:
        """Enrich device information"""
        if device_info.user_agent:
            # Simple user agent parsing (in production, use a proper library)
            ua = device_info.user_agent.lower()
            
            # Operating System detection
            if 'windows' in ua:
                device_info.os = 'Windows'
            elif 'macintosh' in ua or 'mac os' in ua:
                device_info.os = 'macOS'
            elif 'linux' in ua:
                device_info.os = 'Linux'
            elif 'android' in ua:
                device_info.os = 'Android'
                device_info.is_mobile = True
            elif 'iphone' in ua or 'ipad' in ua:
                device_info.os = 'iOS'
                device_info.is_mobile = True
            
            # Browser detection
            if 'chrome' in ua:
                device_info.browser = 'Chrome'
            elif 'firefox' in ua:
                device_info.browser = 'Firefox'
            elif 'safari' in ua:
                device_info.browser = 'Safari'
            elif 'edge' in ua:
                device_info.browser = 'Edge'
        
        return device_info
    
    async def _calculate_basic_risk_score(self, event: IdentityEvent) -> float:
        """Calculate basic risk score"""
        score = 0.0
        
        # Event type risk
        high_risk_events = {
            EventType.LOGIN_FAILURE, EventType.ACCOUNT_LOCKED,
            EventType.PRIVILEGE_ESCALATION, EventType.SUSPICIOUS_ACTIVITY,
            EventType.SESSION_HIJACK_DETECTED, EventType.POLICY_VIOLATION
        }
        
        if event.event_type in high_risk_events:
            score += 30.0
        
        # Off-hours access
        if event.timestamp:
            hour = event.timestamp.hour
            if hour < 6 or hour > 22:  # Outside business hours
                score += 15.0
        
        # Geographic risk
        if event.geo_location:
            high_risk_countries = ['CN', 'RU', 'KP', 'IR']
            if event.geo_location.country_code in high_risk_countries:
                score += 25.0
        
        # Network risk
        if event.network_info:
            if event.network_info.tor_detected:
                score += 40.0
            elif event.network_info.vpn_detected:
                score += 20.0
            elif event.network_info.proxy_detected:
                score += 15.0
        
        # Device risk
        if event.device_info and not event.device_info.is_trusted:
            score += 10.0
        
        return min(score, 100.0)  # Cap at 100
    
    def _generate_correlation_id(self, event: IdentityEvent) -> str:
        """Generate correlation ID based on event attributes"""
        correlation_data = f"{event.user_id}:{event.event_type.value}:{event.timestamp.isoformat()}"
        return hashlib.md5(correlation_data.encode()).hexdigest()


class EventStorage:
    """Event storage with SQLite backend"""
    
    def __init__(self, db_path: str = "identity_events.db"):
        self.db_path = db_path
        self.initialized = False
    
    async def initialize(self):
        """Initialize database schema"""
        if self.initialized:
            return
            
        async with aiosqlite.connect(self.db_path) as db:
            # Main events table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS identity_events (
                    event_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    username TEXT,
                    email TEXT,
                    application TEXT,
                    resource TEXT,
                    action TEXT,
                    result TEXT,
                    message TEXT,
                    protocol TEXT,
                    source_system TEXT,
                    correlation_id TEXT,
                    risk_score REAL DEFAULT 0.0,
                    processed_at TEXT,
                    processing_time_ms REAL,
                    enrichment_status TEXT,
                    raw_data TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Network information table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS event_network_info (
                    event_id TEXT PRIMARY KEY,
                    source_ip TEXT NOT NULL,
                    destination_ip TEXT,
                    source_port INTEGER,
                    destination_port INTEGER,
                    protocol TEXT,
                    vpn_detected BOOLEAN DEFAULT 0,
                    proxy_detected BOOLEAN DEFAULT 0,
                    tor_detected BOOLEAN DEFAULT 0,
                    FOREIGN KEY (event_id) REFERENCES identity_events (event_id)
                )
            """)
            
            # Device information table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS event_device_info (
                    event_id TEXT PRIMARY KEY,
                    device_id TEXT,
                    device_type TEXT,
                    os TEXT,
                    os_version TEXT,
                    browser TEXT,
                    browser_version TEXT,
                    user_agent TEXT,
                    screen_resolution TEXT,
                    is_mobile BOOLEAN DEFAULT 0,
                    is_trusted BOOLEAN DEFAULT 0,
                    FOREIGN KEY (event_id) REFERENCES identity_events (event_id)
                )
            """)
            
            # Session information table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS event_session_info (
                    event_id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    session_start TEXT,
                    session_duration INTEGER,
                    concurrent_sessions INTEGER DEFAULT 1,
                    session_token_hash TEXT,
                    idle_time INTEGER,
                    FOREIGN KEY (event_id) REFERENCES identity_events (event_id)
                )
            """)
            
            # Geolocation table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS event_geolocation (
                    event_id TEXT PRIMARY KEY,
                    country TEXT,
                    country_code TEXT,
                    city TEXT,
                    region TEXT,
                    latitude REAL,
                    longitude REAL,
                    timezone TEXT,
                    isp TEXT,
                    organization TEXT,
                    asn TEXT,
                    FOREIGN KEY (event_id) REFERENCES identity_events (event_id)
                )
            """)
            
            # Create indexes for performance
            indexes = [
                "CREATE INDEX IF NOT EXISTS idx_events_timestamp ON identity_events(timestamp)",
                "CREATE INDEX IF NOT EXISTS idx_events_user_id ON identity_events(user_id)",
                "CREATE INDEX IF NOT EXISTS idx_events_type ON identity_events(event_type)",
                "CREATE INDEX IF NOT EXISTS idx_events_severity ON identity_events(severity)",
                "CREATE INDEX IF NOT EXISTS idx_events_correlation ON identity_events(correlation_id)",
                "CREATE INDEX IF NOT EXISTS idx_events_risk_score ON identity_events(risk_score)",
                "CREATE INDEX IF NOT EXISTS idx_network_source_ip ON event_network_info(source_ip)",
                "CREATE INDEX IF NOT EXISTS idx_device_device_id ON event_device_info(device_id)",
                "CREATE INDEX IF NOT EXISTS idx_session_session_id ON event_session_info(session_id)",
                "CREATE INDEX IF NOT EXISTS idx_geo_country ON event_geolocation(country_code)"
            ]
            
            for index_sql in indexes:
                await db.execute(index_sql)
            
            await db.commit()
        
        self.initialized = True
        logging.info("Event storage initialized successfully")
    
    async def store_event(self, event: IdentityEvent) -> bool:
        """Store event in database"""
        if not self.initialized:
            await self.initialize()
        
        try:
            async with aiosqlite.connect(self.db_path) as db:
                # Store main event
                await db.execute("""
                    INSERT OR REPLACE INTO identity_events (
                        event_id, timestamp, event_type, severity, user_id, username,
                        email, application, resource, action, result, message,
                        protocol, source_system, correlation_id, risk_score,
                        processed_at, processing_time_ms, enrichment_status, raw_data
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    event.event_id,
                    event.timestamp.isoformat() if event.timestamp else None,
                    event.event_type.value if event.event_type else None,
                    event.severity.value if event.severity else None,
                    event.user_id,
                    event.username,
                    event.email,
                    event.application,
                    event.resource,
                    event.action,
                    event.result,
                    event.message,
                    event.protocol.value if event.protocol else None,
                    event.source_system,
                    event.correlation_id,
                    event.risk_score,
                    event.processed_at.isoformat() if event.processed_at else None,
                    event.processing_time_ms,
                    event.enrichment_status,
                    json.dumps(event.raw_data) if event.raw_data else None
                ))
                
                # Store network info
                if event.network_info:
                    await db.execute("""
                        INSERT OR REPLACE INTO event_network_info (
                            event_id, source_ip, destination_ip, source_port,
                            destination_port, protocol, vpn_detected, proxy_detected, tor_detected
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        event.event_id,
                        event.network_info.source_ip,
                        event.network_info.destination_ip,
                        event.network_info.source_port,
                        event.network_info.destination_port,
                        event.network_info.protocol,
                        event.network_info.vpn_detected,
                        event.network_info.proxy_detected,
                        event.network_info.tor_detected
                    ))
                
                # Store device info
                if event.device_info:
                    await db.execute("""
                        INSERT OR REPLACE INTO event_device_info (
                            event_id, device_id, device_type, os, os_version,
                            browser, browser_version, user_agent, screen_resolution,
                            is_mobile, is_trusted
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        event.event_id,
                        event.device_info.device_id,
                        event.device_info.device_type,
                        event.device_info.os,
                        event.device_info.os_version,
                        event.device_info.browser,
                        event.device_info.browser_version,
                        event.device_info.user_agent,
                        event.device_info.screen_resolution,
                        event.device_info.is_mobile,
                        event.device_info.is_trusted
                    ))
                
                # Store session info
                if event.session_info:
                    await db.execute("""
                        INSERT OR REPLACE INTO event_session_info (
                            event_id, session_id, session_start, session_duration,
                            concurrent_sessions, session_token_hash, idle_time
                        ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """, (
                        event.event_id,
                        event.session_info.session_id,
                        event.session_info.session_start.isoformat() if event.session_info.session_start else None,
                        event.session_info.session_duration,
                        event.session_info.concurrent_sessions,
                        event.session_info.session_token_hash,
                        event.session_info.idle_time
                    ))
                
                # Store geolocation
                if event.geo_location:
                    await db.execute("""
                        INSERT OR REPLACE INTO event_geolocation (
                            event_id, country, country_code, city, region,
                            latitude, longitude, timezone, isp, organization, asn
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        event.event_id,
                        event.geo_location.country,
                        event.geo_location.country_code,
                        event.geo_location.city,
                        event.geo_location.region,
                        event.geo_location.latitude,
                        event.geo_location.longitude,
                        event.geo_location.timezone,
                        event.geo_location.isp,
                        event.geo_location.organization,
                        event.geo_location.asn
                    ))
                
                await db.commit()
                return True
                
        except Exception as e:
            logging.error(f"Failed to store event {event.event_id}: {e}")
            return False
    
    async def get_events(self, 
                        user_id: Optional[str] = None,
                        event_type: Optional[EventType] = None,
                        start_time: Optional[datetime] = None,
                        end_time: Optional[datetime] = None,
                        limit: int = 1000) -> List[IdentityEvent]:
        """Retrieve events from storage"""
        if not self.initialized:
            await self.initialize()
        
        query = "SELECT * FROM identity_events WHERE 1=1"
        params = []
        
        if user_id:
            query += " AND user_id = ?"
            params.append(user_id)
        
        if event_type:
            query += " AND event_type = ?"
            params.append(event_type.value)
        
        if start_time:
            query += " AND timestamp >= ?"
            params.append(start_time.isoformat())
        
        if end_time:
            query += " AND timestamp <= ?"
            params.append(end_time.isoformat())
        
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        
        try:
            async with aiosqlite.connect(self.db_path) as db:
                async with db.execute(query, params) as cursor:
                    rows = await cursor.fetchall()
                    columns = [description[0] for description in cursor.description]
                    
                    events = []
                    for row in rows:
                        row_dict = dict(zip(columns, row))
                        event = self._row_to_event(row_dict)
                        events.append(event)
                    
                    return events
                    
        except Exception as e:
            logging.error(f"Failed to retrieve events: {e}")
            return []
    
    def _row_to_event(self, row: Dict[str, Any]) -> IdentityEvent:
        """Convert database row to IdentityEvent object"""
        return IdentityEvent(
            event_id=row['event_id'],
            timestamp=datetime.fromisoformat(row['timestamp']) if row['timestamp'] else None,
            event_type=EventType(row['event_type']) if row['event_type'] else None,
            severity=EventSeverity(row['severity']) if row['severity'] else None,
            user_id=row['user_id'],
            username=row['username'],
            email=row['email'],
            application=row['application'],
            resource=row['resource'],
            action=row['action'],
            result=row['result'],
            message=row['message'],
            protocol=ProtocolType(row['protocol']) if row['protocol'] else None,
            source_system=row['source_system'],
            correlation_id=row['correlation_id'],
            risk_score=row['risk_score'] or 0.0,
            processed_at=datetime.fromisoformat(row['processed_at']) if row['processed_at'] else None,
            processing_time_ms=row['processing_time_ms'],
            enrichment_status=row['enrichment_status'],
            raw_data=json.loads(row['raw_data']) if row['raw_data'] else None
        )


class KafkaEventProcessor:
    """Kafka-based event processing"""
    
    def __init__(self, 
                 bootstrap_servers: List[str],
                 input_topic: str = "identity-events-raw",
                 output_topic: str = "identity-events-processed",
                 consumer_group: str = "identity-processor"):
        self.bootstrap_servers = bootstrap_servers
        self.input_topic = input_topic
        self.output_topic = output_topic
        self.consumer_group = consumer_group
        self.producer = None
        self.consumer = None
        self.running = False
        
    async def start_producer(self):
        """Start Kafka producer"""
        try:
            self.producer = KafkaProducer(
                bootstrap_servers=self.bootstrap_servers,
                value_serializer=lambda x: json.dumps(x, default=str).encode('utf-8'),
                key_serializer=lambda x: x.encode('utf-8') if x else None,
                acks='all',
                retries=3,
                batch_size=16384,
                linger_ms=10,
                buffer_memory=33554432
            )
            logging.info("Kafka producer started successfully")
        except Exception as e:
            logging.error(f"Failed to start Kafka producer: {e}")
            raise
    
    async def start_consumer(self):
        """Start Kafka consumer"""
        try:
            self.consumer = KafkaConsumer(
                self.input_topic,
                bootstrap_servers=self.bootstrap_servers,
                group_id=self.consumer_group,
                value_deserializer=lambda x: json.loads(x.decode('utf-8')),
                key_deserializer=lambda x: x.decode('utf-8') if x else None,
                auto_offset_reset='earliest',
                enable_auto_commit=True,
                auto_commit_interval_ms=1000,
                max_poll_records=500,
                session_timeout_ms=30000,
                heartbeat_interval_ms=3000
            )
            logging.info("Kafka consumer started successfully")
        except Exception as e:
            logging.error(f"Failed to start Kafka consumer: {e}")
            raise
    
    async def publish_event(self, event: IdentityEvent, topic: Optional[str] = None) -> bool:
        """Publish event to Kafka topic"""
        if not self.producer:
            await self.start_producer()
        
        try:
            target_topic = topic or self.output_topic
            event_dict = asdict(event)
            
            # Convert datetime objects to ISO strings
            for key, value in event_dict.items():
                if isinstance(value, datetime):
                    event_dict[key] = value.isoformat()
            
            # Send message
            future = self.producer.send(
                target_topic,
                key=event.event_id,
                value=event_dict
            )
            
            # Wait for acknowledgment
            record_metadata = future.get(timeout=10)
            logging.debug(f"Event {event.event_id} published to {record_metadata.topic}:{record_metadata.partition}")
            
            return True
            
        except Exception as e:
            logging.error(f"Failed to publish event {event.event_id}: {e}")
            return False
    
    async def consume_events(self, processor_func: Callable[[Dict[str, Any]], None]):
        """Consume events from Kafka topic"""
        if not self.consumer:
            await self.start_consumer()
        
        self.running = True
        logging.info(f"Starting event consumption from topic: {self.input_topic}")
        
        try:
            while self.running:
                msg_pack = self.consumer.poll(timeout_ms=1000)
                
                for topic_partition, messages in msg_pack.items():
                    for message in messages:
                        try:
                            # Process message
                            await processor_func(message.value)
                            
                        except Exception as e:
                            logging.error(f"Error processing message: {e}")
                            # Could implement dead letter queue here
                            
        except Exception as e:
            logging.error(f"Consumer error: {e}")
        finally:
            if self.consumer:
                self.consumer.close()
    
    def stop_consumer(self):
        """Stop event consumption"""
        self.running = False


class IdentityEventProcessor:
    """Main event processing orchestrator for ISECTECH platform"""
    
    def __init__(self, 
                 db_path: str = "identity_events.db",
                 redis_url: str = "redis://localhost:6379",
                 kafka_servers: Optional[List[str]] = None,
                 geoip_db_path: Optional[str] = None,
                 encryption_key: Optional[str] = None):
        
        # Core components
        self.validator = EventValidator()
        self.enricher = EventEnricher(geoip_db_path)
        self.storage = EventStorage(db_path)
        
        # External systems
        self.redis_client = None
        self.kafka_processor = None
        if kafka_servers:
            self.kafka_processor = KafkaEventProcessor(kafka_servers)
        
        # Configuration
        self.redis_url = redis_url
        self.encryption_key = encryption_key
        self.processing_stats = {
            'total_processed': 0,
            'successful': 0,
            'failed': 0,
            'validation_errors': 0,
            'enrichment_errors': 0,
            'storage_errors': 0,
            'start_time': datetime.now(timezone.utc)
        }
        
        # Thread pool for CPU-intensive tasks
        self.thread_pool = ThreadPoolExecutor(max_workers=4)
        
        # Event queues for different priorities
        self.high_priority_queue = Queue(maxsize=1000)
        self.normal_priority_queue = Queue(maxsize=5000)
        self.low_priority_queue = Queue(maxsize=10000)
        
        logging.info("Identity Event Processor initialized")
    
    async def initialize(self):
        """Initialize all components"""
        # Initialize storage
        await self.storage.initialize()
        
        # Initialize Redis connection
        try:
            self.redis_client = redis.from_url(self.redis_url)
            await self.redis_client.ping()
            logging.info("Redis connection established")
        except Exception as e:
            logging.warning(f"Redis connection failed: {e}")
        
        # Initialize Kafka if configured
        if self.kafka_processor:
            try:
                await self.kafka_processor.start_producer()
                logging.info("Kafka producer initialized")
            except Exception as e:
                logging.warning(f"Kafka initialization failed: {e}")
        
        logging.info("Identity Event Processor fully initialized")
    
    async def process_event(self, event: IdentityEvent) -> bool:
        """Process a single identity event"""
        start_time = time.time()
        
        try:
            # Update processing stats
            self.processing_stats['total_processed'] += 1
            
            # Step 1: Validation
            is_valid, errors = self.validator.validate_event(event)
            if not is_valid:
                self.processing_stats['validation_errors'] += 1
                event.validation_errors = errors
                logging.warning(f"Event validation failed: {errors}")
                return False
            
            # Step 2: Sanitization
            event = self.validator.sanitize_event(event)
            
            # Step 3: Enrichment
            try:
                event = await self.enricher.enrich_event(event)
            except Exception as e:
                self.processing_stats['enrichment_errors'] += 1
                logging.error(f"Event enrichment failed: {e}")
                event.enrichment_status = f"failed: {str(e)}"
            
            # Step 4: Storage
            event.processed_at = datetime.now(timezone.utc)
            stored = await self.storage.store_event(event)
            
            if not stored:
                self.processing_stats['storage_errors'] += 1
                return False
            
            # Step 5: Real-time processing
            await self._process_real_time(event)
            
            # Step 6: Kafka publishing (if configured)
            if self.kafka_processor:
                await self.kafka_processor.publish_event(event)
            
            # Step 7: Cache recent events
            if self.redis_client:
                await self._cache_event(event)
            
            self.processing_stats['successful'] += 1
            
            # Record total processing time
            processing_time = (time.time() - start_time) * 1000
            event.processing_time_ms = processing_time
            
            logging.debug(f"Event {event.event_id} processed successfully in {processing_time:.2f}ms")
            return True
            
        except Exception as e:
            self.processing_stats['failed'] += 1
            logging.error(f"Event processing failed for {event.event_id}: {e}")
            return False
    
    async def process_batch(self, events: List[IdentityEvent]) -> Dict[str, int]:
        """Process a batch of events concurrently"""
        batch_start = time.time()
        
        # Process events concurrently
        tasks = [self.process_event(event) for event in events]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Collect statistics
        stats = {
            'total': len(events),
            'successful': sum(1 for r in results if r is True),
            'failed': sum(1 for r in results if r is not True),
            'processing_time_ms': (time.time() - batch_start) * 1000
        }
        
        logging.info(f"Batch processed: {stats}")
        return stats
    
    async def _process_real_time(self, event: IdentityEvent):
        """Real-time event processing for immediate alerts"""
        # Check for critical events
        if event.severity == EventSeverity.CRITICAL or event.risk_score > 80:
            await self._handle_critical_event(event)
        
        # Update user session tracking
        if event.session_info:
            await self._update_session_tracking(event)
        
        # Update behavioral baselines
        if event.event_type in [EventType.LOGIN_SUCCESS, EventType.RESOURCE_ACCESS]:
            await self._update_behavioral_baseline(event)
    
    async def _handle_critical_event(self, event: IdentityEvent):
        """Handle critical security events"""
        alert_key = f"critical_alert:{event.event_id}"
        
        if self.redis_client:
            # Store alert with 24-hour expiration
            alert_data = {
                'event_id': event.event_id,
                'user_id': event.user_id,
                'event_type': event.event_type.value,
                'risk_score': event.risk_score,
                'timestamp': event.timestamp.isoformat(),
                'message': event.message
            }
            
            await self.redis_client.setex(
                alert_key,
                86400,  # 24 hours
                json.dumps(alert_data)
            )
            
            # Add to alerts queue
            await self.redis_client.lpush("security_alerts", json.dumps(alert_data))
            
        logging.critical(f"Critical security event detected: {event.event_id}")
    
    async def _update_session_tracking(self, event: IdentityEvent):
        """Update active session tracking"""
        if not self.redis_client or not event.session_info:
            return
        
        session_key = f"session:{event.session_info.session_id}"
        session_data = {
            'user_id': event.user_id,
            'last_activity': event.timestamp.isoformat(),
            'event_count': 1,
            'risk_score': event.risk_score
        }
        
        # Check if session exists
        existing = await self.redis_client.get(session_key)
        if existing:
            existing_data = json.loads(existing)
            session_data['event_count'] = existing_data.get('event_count', 0) + 1
        
        # Update session with 4-hour expiration
        await self.redis_client.setex(
            session_key,
            14400,  # 4 hours
            json.dumps(session_data)
        )
    
    async def _update_behavioral_baseline(self, event: IdentityEvent):
        """Update user behavioral baseline"""
        if not self.redis_client:
            return
        
        baseline_key = f"baseline:{event.user_id}"
        
        # Simple baseline tracking (in production, this would be more sophisticated)
        baseline_data = {
            'last_login': event.timestamp.isoformat(),
            'login_count': 1,
            'common_locations': [],
            'common_devices': []
        }
        
        # Add geolocation to common locations
        if event.geo_location and event.geo_location.city:
            baseline_data['common_locations'].append({
                'city': event.geo_location.city,
                'country': event.geo_location.country,
                'timestamp': event.timestamp.isoformat()
            })
        
        # Add device to common devices
        if event.device_info and event.device_info.device_id:
            baseline_data['common_devices'].append({
                'device_id': event.device_info.device_id,
                'os': event.device_info.os,
                'browser': event.device_info.browser,
                'timestamp': event.timestamp.isoformat()
            })
        
        await self.redis_client.setex(
            baseline_key,
            2592000,  # 30 days
            json.dumps(baseline_data)
        )
    
    async def _cache_event(self, event: IdentityEvent):
        """Cache recent events for fast retrieval"""
        if not self.redis_client:
            return
        
        # Cache event for 1 hour
        event_key = f"event:{event.event_id}"
        event_data = asdict(event)
        
        # Convert datetime objects to strings
        for key, value in event_data.items():
            if isinstance(value, datetime):
                event_data[key] = value.isoformat()
        
        await self.redis_client.setex(
            event_key,
            3600,  # 1 hour
            json.dumps(event_data, default=str)
        )
        
        # Add to user's recent events list
        user_events_key = f"user_events:{event.user_id}"
        await self.redis_client.lpush(user_events_key, event.event_id)
        await self.redis_client.ltrim(user_events_key, 0, 99)  # Keep last 100 events
        await self.redis_client.expire(user_events_key, 86400)  # 24 hours
    
    async def get_processing_stats(self) -> Dict[str, Any]:
        """Get processing statistics"""
        uptime = datetime.now(timezone.utc) - self.processing_stats['start_time']
        
        stats = self.processing_stats.copy()
        stats['uptime_seconds'] = uptime.total_seconds()
        stats['events_per_second'] = (
            stats['total_processed'] / uptime.total_seconds() 
            if uptime.total_seconds() > 0 else 0
        )
        stats['success_rate'] = (
            stats['successful'] / stats['total_processed'] 
            if stats['total_processed'] > 0 else 0
        )
        
        return stats
    
    async def get_recent_alerts(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent security alerts"""
        if not self.redis_client:
            return []
        
        alerts = await self.redis_client.lrange("security_alerts", 0, limit - 1)
        return [json.loads(alert) for alert in alerts]
    
    async def get_user_sessions(self, user_id: str) -> List[Dict[str, Any]]:
        """Get active sessions for a user"""
        if not self.redis_client:
            return []
        
        pattern = f"session:*"
        sessions = []
        
        async for key in self.redis_client.scan_iter(match=pattern):
            session_data = await self.redis_client.get(key)
            if session_data:
                data = json.loads(session_data)
                if data.get('user_id') == user_id:
                    data['session_id'] = key.decode().split(':')[1]
                    sessions.append(data)
        
        return sessions
    
    def create_event_from_dict(self, event_data: Dict[str, Any]) -> IdentityEvent:
        """Create IdentityEvent from dictionary data"""
        # Handle timestamp conversion
        timestamp = event_data.get('timestamp')
        if isinstance(timestamp, str):
            timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        elif timestamp is None:
            timestamp = datetime.now(timezone.utc)
        
        # Handle enums
        event_type = EventType(event_data.get('event_type', 'login_success'))
        severity = EventSeverity(event_data.get('severity', 'medium'))
        protocol = None
        if event_data.get('protocol'):
            protocol = ProtocolType(event_data['protocol'])
        
        # Create network info
        network_info = None
        if event_data.get('source_ip'):
            network_info = NetworkInfo(
                source_ip=event_data['source_ip'],
                destination_ip=event_data.get('destination_ip'),
                source_port=event_data.get('source_port'),
                destination_port=event_data.get('destination_port'),
                protocol=event_data.get('network_protocol'),
                vpn_detected=event_data.get('vpn_detected', False),
                proxy_detected=event_data.get('proxy_detected', False),
                tor_detected=event_data.get('tor_detected', False)
            )
        
        # Create device info
        device_info = None
        if event_data.get('user_agent'):
            device_info = DeviceInfo(
                device_id=event_data.get('device_id'),
                device_type=event_data.get('device_type'),
                os=event_data.get('os'),
                os_version=event_data.get('os_version'),
                browser=event_data.get('browser'),
                browser_version=event_data.get('browser_version'),
                user_agent=event_data.get('user_agent'),
                screen_resolution=event_data.get('screen_resolution'),
                is_mobile=event_data.get('is_mobile', False),
                is_trusted=event_data.get('is_trusted', False)
            )
        
        # Create session info
        session_info = None
        if event_data.get('session_id'):
            session_start = event_data.get('session_start')
            if isinstance(session_start, str):
                session_start = datetime.fromisoformat(session_start.replace('Z', '+00:00'))
            
            session_info = SessionInfo(
                session_id=event_data['session_id'],
                session_start=session_start,
                session_duration=event_data.get('session_duration'),
                concurrent_sessions=event_data.get('concurrent_sessions', 1),
                session_token_hash=event_data.get('session_token_hash'),
                idle_time=event_data.get('idle_time')
            )
        
        return IdentityEvent(
            event_id=event_data.get('event_id', str(uuid.uuid4())),
            timestamp=timestamp,
            event_type=event_type,
            severity=severity,
            user_id=event_data['user_id'],
            username=event_data.get('username'),
            email=event_data.get('email'),
            application=event_data.get('application'),
            resource=event_data.get('resource'),
            action=event_data.get('action'),
            result=event_data.get('result'),
            message=event_data.get('message'),
            protocol=protocol,
            source_system=event_data.get('source_system'),
            correlation_id=event_data.get('correlation_id'),
            risk_score=event_data.get('risk_score', 0.0),
            network_info=network_info,
            device_info=device_info,
            session_info=session_info,
            context=event_data.get('context'),
            raw_data=event_data.get('raw_data'),
            tags=event_data.get('tags')
        )
    
    async def shutdown(self):
        """Gracefully shutdown the processor"""
        logging.info("Shutting down Identity Event Processor")
        
        # Stop Kafka consumer
        if self.kafka_processor:
            self.kafka_processor.stop_consumer()
        
        # Close Redis connection
        if self.redis_client:
            await self.redis_client.close()
        
        # Shutdown thread pool
        self.thread_pool.shutdown(wait=True)
        
        logging.info("Identity Event Processor shutdown complete")


# Example usage and testing
async def example_usage():
    """Example usage of the Identity Event Processor"""
    
    # Initialize processor
    processor = IdentityEventProcessor(
        db_path="test_identity_events.db",
        redis_url="redis://localhost:6379"
    )
    
    await processor.initialize()
    
    # Create sample event
    sample_event = IdentityEvent(
        event_id=str(uuid.uuid4()),
        timestamp=datetime.now(timezone.utc),
        event_type=EventType.LOGIN_SUCCESS,
        severity=EventSeverity.INFO,
        user_id="user123",
        username="john.doe",
        email="john.doe@isectech.com",
        application="web-portal",
        resource="dashboard",
        action="login",
        result="success",
        message="User logged in successfully",
        protocol=ProtocolType.SAML,
        source_system="identity-provider",
        network_info=NetworkInfo(
            source_ip="192.168.1.100",
            vpn_detected=False,
            proxy_detected=False
        ),
        device_info=DeviceInfo(
            device_id="device123",
            os="Windows",
            browser="Chrome",
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            is_trusted=True
        ),
        session_info=SessionInfo(
            session_id="session123",
            session_start=datetime.now(timezone.utc),
            concurrent_sessions=1
        )
    )
    
    # Process the event
    success = await processor.process_event(sample_event)
    print(f"Event processed: {success}")
    
    # Get processing stats
    stats = await processor.get_processing_stats()
    print(f"Processing stats: {stats}")
    
    # Cleanup
    await processor.shutdown()


if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Run example
    asyncio.run(example_usage())