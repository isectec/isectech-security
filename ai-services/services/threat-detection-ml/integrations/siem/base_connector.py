"""
Base SIEM Connector

Abstract base class defining the interface for SIEM platform integrations
with production-grade connection management, authentication, and event handling.
"""

import asyncio
import logging
import json
import ssl
import hashlib
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union, Callable, AsyncGenerator
from dataclasses import dataclass, field
from enum import Enum, IntEnum
import aiohttp
import websockets
from pydantic import BaseModel, Field, validator
import backoff
from cryptography.fernet import Fernet

logger = logging.getLogger(__name__)

class SiemPlatform(str, Enum):
    """Supported SIEM platforms"""
    SPLUNK = "splunk"
    QRADAR = "qradar" 
    SENTINEL = "sentinel"
    ELASTIC = "elastic"
    CHRONICLE = "chronicle"

class EventSeverity(IntEnum):
    """Event severity levels aligned with SIEM standards"""
    CRITICAL = 1
    HIGH = 2
    MEDIUM = 3
    LOW = 4
    INFO = 5

class ConnectionStatus(str, Enum):
    """SIEM connection status"""
    CONNECTED = "connected"
    CONNECTING = "connecting"
    DISCONNECTED = "disconnected"
    ERROR = "error"
    AUTHENTICATION_FAILED = "auth_failed"

@dataclass
class SiemConfig:
    """SIEM connection configuration with security settings"""
    platform: SiemPlatform
    host: str
    port: int = 443
    username: str = ""
    password: str = ""
    api_key: str = ""
    token: str = ""
    ssl_verify: bool = True
    ssl_cert: Optional[str] = None
    ssl_key: Optional[str] = None
    timeout: int = 30
    max_retries: int = 3
    retry_delay: float = 1.0
    connection_pool_size: int = 10
    rate_limit_per_second: int = 100
    encryption_key: Optional[str] = None
    custom_headers: Dict[str, str] = field(default_factory=dict)
    
    def __post_init__(self):
        """Post-initialization validation and setup"""
        if self.encryption_key:
            self._cipher = Fernet(self.encryption_key.encode())
        else:
            self._cipher = None
            
    def encrypt_credential(self, credential: str) -> str:
        """Encrypt sensitive credential"""
        if self._cipher and credential:
            return self._cipher.encrypt(credential.encode()).decode()
        return credential
        
    def decrypt_credential(self, encrypted_credential: str) -> str:
        """Decrypt sensitive credential"""
        if self._cipher and encrypted_credential:
            try:
                return self._cipher.decrypt(encrypted_credential.encode()).decode()
            except Exception as e:
                logger.error(f"Failed to decrypt credential: {e}")
                return encrypted_credential
        return encrypted_credential

class SiemEvent(BaseModel):
    """Standardized SIEM event structure"""
    id: str = Field(description="Unique event identifier")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    source: str = Field(description="Event source system")
    event_type: str = Field(description="Type of security event")
    severity: EventSeverity = Field(default=EventSeverity.MEDIUM)
    category: str = Field(description="Event category (e.g., authentication, network)")
    message: str = Field(description="Event description")
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    user_id: Optional[str] = None
    asset_id: Optional[str] = None
    raw_data: Dict[str, Any] = Field(default_factory=dict)
    tags: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat() if v else None
        }
    
    @validator('timestamp', pre=True)
    def parse_timestamp(cls, v):
        if isinstance(v, str):
            try:
                return datetime.fromisoformat(v.replace('Z', '+00:00'))
            except ValueError:
                return datetime.utcnow()
        return v or datetime.utcnow()
    
    def to_json(self) -> str:
        """Convert to JSON string"""
        return self.json(exclude_none=True)
    
    def get_hash(self) -> str:
        """Generate event hash for deduplication"""
        hash_data = f"{self.source}{self.event_type}{self.message}{self.source_ip}{self.destination_ip}"
        return hashlib.sha256(hash_data.encode()).hexdigest()[:16]

class SiemResponse(BaseModel):
    """Standard SIEM API response"""
    success: bool = Field(description="Operation success status")
    status_code: int = Field(description="HTTP status code")
    message: str = Field(description="Response message")
    data: Optional[Dict[str, Any]] = Field(default=None, description="Response data")
    error_details: Optional[str] = Field(default=None, description="Error details")
    request_id: Optional[str] = Field(default=None, description="Request tracking ID")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    
    def is_success(self) -> bool:
        """Check if response indicates success"""
        return self.success and 200 <= self.status_code < 300

class BaseSiemConnector(ABC):
    """
    Abstract base class for SIEM platform connectors
    
    Provides standardized interface for connecting to different SIEM platforms
    with built-in authentication, connection pooling, rate limiting, and error handling.
    """
    
    def __init__(self, config: SiemConfig):
        self.config = config
        self.platform = config.platform
        self._session: Optional[aiohttp.ClientSession] = None
        self._websocket: Optional[websockets.WebSocketServerProtocol] = None
        self._connection_status = ConnectionStatus.DISCONNECTED
        self._last_heartbeat = datetime.utcnow()
        self._event_callbacks: List[Callable[[SiemEvent], None]] = []
        self._rate_limiter = asyncio.Semaphore(config.rate_limit_per_second)
        self._metrics = {
            'events_sent': 0,
            'events_received': 0,
            'connection_errors': 0,
            'api_calls': 0,
            'last_activity': datetime.utcnow()
        }
        
        # Setup SSL context
        self._ssl_context = None
        if config.ssl_verify:
            self._ssl_context = ssl.create_default_context()
            if config.ssl_cert and config.ssl_key:
                self._ssl_context.load_cert_chain(config.ssl_cert, config.ssl_key)
                
        logger.info(f"Initialized {self.platform} SIEM connector for {config.host}")
    
    @abstractmethod
    async def connect(self) -> bool:
        """Establish connection to SIEM platform"""
        pass
    
    @abstractmethod
    async def disconnect(self) -> bool:
        """Close connection to SIEM platform"""
        pass
    
    @abstractmethod
    async def authenticate(self) -> bool:
        """Authenticate with SIEM platform"""
        pass
    
    @abstractmethod
    async def send_event(self, event: SiemEvent) -> SiemResponse:
        """Send event to SIEM platform"""
        pass
    
    @abstractmethod
    async def query_events(
        self,
        query: str,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 1000
    ) -> List[SiemEvent]:
        """Query events from SIEM platform"""
        pass
    
    @abstractmethod
    async def create_alert(
        self,
        title: str,
        description: str,
        severity: EventSeverity = EventSeverity.MEDIUM,
        metadata: Optional[Dict[str, Any]] = None
    ) -> SiemResponse:
        """Create alert in SIEM platform"""
        pass
    
    async def start_event_stream(self) -> AsyncGenerator[SiemEvent, None]:
        """Start real-time event stream from SIEM"""
        while self._connection_status == ConnectionStatus.CONNECTED:
            try:
                async for event in self._stream_events():
                    self._metrics['events_received'] += 1
                    self._metrics['last_activity'] = datetime.utcnow()
                    yield event
                    
            except Exception as e:
                logger.error(f"Error in event stream: {e}")
                await asyncio.sleep(5)
                if self._connection_status == ConnectionStatus.CONNECTED:
                    await self._reconnect()
    
    @abstractmethod
    async def _stream_events(self) -> AsyncGenerator[SiemEvent, None]:
        """Platform-specific event streaming implementation"""
        pass
    
    async def health_check(self) -> bool:
        """Check SIEM connection health"""
        try:
            response = await self._make_api_call("GET", "/api/health", timeout=10)
            return response.is_success()
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            return False
    
    @backoff.on_exception(
        backoff.expo,
        Exception,
        max_tries=3,
        max_time=300
    )
    async def _make_api_call(
        self,
        method: str,
        endpoint: str,
        data: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout: Optional[int] = None
    ) -> SiemResponse:
        """Make authenticated API call to SIEM platform"""
        async with self._rate_limiter:
            if not self._session:
                await self.connect()
                
            url = f"{self._get_base_url()}{endpoint}"
            timeout = timeout or self.config.timeout
            
            # Prepare headers
            call_headers = self._get_auth_headers()
            if headers:
                call_headers.update(headers)
            call_headers.update(self.config.custom_headers)
            
            try:
                self._metrics['api_calls'] += 1
                
                async with self._session.request(
                    method=method,
                    url=url,
                    json=data,
                    params=params,
                    headers=call_headers,
                    timeout=aiohttp.ClientTimeout(total=timeout),
                    ssl=self._ssl_context
                ) as response:
                    
                    response_data = None
                    try:
                        response_data = await response.json()
                    except Exception:
                        response_data = {"text": await response.text()}
                    
                    return SiemResponse(
                        success=response.status < 400,
                        status_code=response.status,
                        message=response.reason or "API call completed",
                        data=response_data,
                        request_id=response.headers.get('X-Request-ID')
                    )
                    
            except asyncio.TimeoutError:
                logger.error(f"API call timeout: {method} {endpoint}")
                raise
            except Exception as e:
                logger.error(f"API call failed: {method} {endpoint} - {e}")
                self._metrics['connection_errors'] += 1
                raise
    
    @abstractmethod
    def _get_base_url(self) -> str:
        """Get base URL for SIEM platform"""
        pass
    
    @abstractmethod 
    def _get_auth_headers(self) -> Dict[str, str]:
        """Get authentication headers"""
        pass
    
    async def _reconnect(self) -> bool:
        """Attempt to reconnect to SIEM platform"""
        logger.info(f"Attempting to reconnect to {self.platform}")
        await self.disconnect()
        return await self.connect()
    
    def add_event_callback(self, callback: Callable[[SiemEvent], None]) -> None:
        """Add callback for received events"""
        self._event_callbacks.append(callback)
    
    def remove_event_callback(self, callback: Callable[[SiemEvent], None]) -> None:
        """Remove event callback"""
        if callback in self._event_callbacks:
            self._event_callbacks.remove(callback)
    
    async def _notify_event_callbacks(self, event: SiemEvent) -> None:
        """Notify all registered event callbacks"""
        for callback in self._event_callbacks:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(event)
                else:
                    callback(event)
            except Exception as e:
                logger.error(f"Error in event callback: {e}")
    
    def get_connection_status(self) -> ConnectionStatus:
        """Get current connection status"""
        return self._connection_status
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get connection and performance metrics"""
        return {
            **self._metrics,
            'connection_status': self._connection_status,
            'last_heartbeat': self._last_heartbeat,
            'uptime_seconds': (datetime.utcnow() - self._metrics['last_activity']).total_seconds()
        }
    
    async def __aenter__(self):
        """Async context manager entry"""
        await self.connect()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self.disconnect()
        
    def __str__(self) -> str:
        return f"SiemConnector({self.platform}, {self.config.host}:{self.config.port})"
    
    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} platform={self.platform} host={self.config.host}>"