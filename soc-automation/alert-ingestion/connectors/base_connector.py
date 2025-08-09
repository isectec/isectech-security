"""
Base Connector Class for Alert Sources

Provides the foundation for all alert source connectors with common functionality
for connection management, error handling, rate limiting, and health monitoring.
"""

import asyncio
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Dict, Any, AsyncGenerator, Optional, List
from enum import Enum
from dataclasses import dataclass
import structlog

logger = structlog.get_logger(__name__)

class ConnectorStatus(Enum):
    """Connector status states"""
    STOPPED = "stopped"
    STARTING = "starting"
    RUNNING = "running"
    ERROR = "error"
    RECONNECTING = "reconnecting"

@dataclass
class ConnectorMetrics:
    """Metrics tracked for each connector"""
    total_alerts: int = 0
    alerts_per_second: float = 0.0
    error_count: int = 0
    last_alert_time: Optional[datetime] = None
    last_error_time: Optional[datetime] = None
    connection_uptime: timedelta = None

class BaseConnector(ABC):
    """
    Abstract base class for all alert source connectors.
    
    Provides:
    - Connection lifecycle management
    - Health monitoring and metrics
    - Rate limiting and backpressure handling
    - Error handling and retry logic
    - Configurable buffering
    - Status reporting
    """
    
    def __init__(self, name: str, config: Dict[str, Any]):
        self.name = name
        self.config = config
        self.status = ConnectorStatus.STOPPED
        self.metrics = ConnectorMetrics()
        
        # Configuration
        self.batch_size = config.get('batch_size', 100)
        self.max_retries = config.get('max_retries', 3)
        self.retry_delay = config.get('retry_delay', 5.0)
        self.rate_limit = config.get('rate_limit', 1000)  # alerts per minute
        self.buffer_size = config.get('buffer_size', 10000)
        self.health_check_interval = config.get('health_check_interval', 60)
        
        # Internal state
        self._running = False
        self._connection_start_time = None
        self._alert_buffer = asyncio.Queue(maxsize=self.buffer_size)
        self._health_check_task = None
        self._rate_limiter = asyncio.Semaphore(self.rate_limit)
        self._last_metrics_time = datetime.now(timezone.utc)
        
        logger.info("Connector initialized",
                   name=self.name,
                   batch_size=self.batch_size,
                   rate_limit=self.rate_limit)
    
    async def start(self):
        """Start the connector"""
        if self._running:
            logger.warning("Connector already running", name=self.name)
            return
        
        self.status = ConnectorStatus.STARTING
        self._running = True
        self._connection_start_time = datetime.now(timezone.utc)
        
        try:
            # Initialize connection
            await self._initialize_connection()
            
            # Start health monitoring
            self._health_check_task = asyncio.create_task(self._health_check_loop())
            
            self.status = ConnectorStatus.RUNNING
            logger.info("Connector started successfully", name=self.name)
            
        except Exception as e:
            self.status = ConnectorStatus.ERROR
            self.metrics.last_error_time = datetime.now(timezone.utc)
            self.metrics.error_count += 1
            logger.error("Failed to start connector", name=self.name, error=str(e))
            raise
    
    async def stop(self):
        """Stop the connector"""
        if not self._running:
            return
        
        self._running = False
        self.status = ConnectorStatus.STOPPED
        
        # Cancel health check task
        if self._health_check_task:
            self._health_check_task.cancel()
            try:
                await self._health_check_task
            except asyncio.CancelledError:
                pass
        
        # Close connection
        await self._close_connection()
        
        logger.info("Connector stopped", name=self.name)
    
    async def get_alerts(self) -> AsyncGenerator[Dict[str, Any], None]:
        """
        Get alerts from the source as an async generator
        
        Yields:
            Alert dictionaries from the source
        """
        if not self._running:
            raise RuntimeError(f"Connector {self.name} is not running")
        
        try:
            async for alert_batch in self._fetch_alerts():
                for alert in alert_batch:
                    # Apply rate limiting
                    await self._rate_limiter.acquire()
                    
                    # Update metrics
                    self.metrics.total_alerts += 1
                    self.metrics.last_alert_time = datetime.now(timezone.utc)
                    self._update_rate_metrics()
                    
                    yield alert
                    
        except Exception as e:
            self.metrics.error_count += 1
            self.metrics.last_error_time = datetime.now(timezone.utc)
            self.status = ConnectorStatus.ERROR
            
            logger.error("Alert fetching failed",
                        name=self.name,
                        error=str(e))
            
            # Attempt reconnection
            if self._running:
                await self._handle_connection_error(e)
            
            raise
    
    def get_status(self) -> Dict[str, Any]:
        """Get connector status and metrics"""
        uptime = None
        if self._connection_start_time:
            uptime = datetime.now(timezone.utc) - self._connection_start_time
            self.metrics.connection_uptime = uptime
        
        return {
            'name': self.name,
            'status': self.status.value,
            'metrics': {
                'total_alerts': self.metrics.total_alerts,
                'alerts_per_second': self.metrics.alerts_per_second,
                'error_count': self.metrics.error_count,
                'last_alert_time': self.metrics.last_alert_time.isoformat() if self.metrics.last_alert_time else None,
                'last_error_time': self.metrics.last_error_time.isoformat() if self.metrics.last_error_time else None,
                'connection_uptime_seconds': uptime.total_seconds() if uptime else None
            },
            'config': {
                'batch_size': self.batch_size,
                'rate_limit': self.rate_limit,
                'buffer_size': self.buffer_size
            }
        }
    
    # Abstract methods to be implemented by subclasses
    
    @abstractmethod
    async def _initialize_connection(self):
        """Initialize connection to the alert source"""
        pass
    
    @abstractmethod
    async def _close_connection(self):
        """Close connection to the alert source"""
        pass
    
    @abstractmethod
    async def _fetch_alerts(self) -> AsyncGenerator[List[Dict[str, Any]], None]:
        """Fetch alerts from the source in batches"""
        pass
    
    @abstractmethod
    async def _health_check(self) -> bool:
        """Perform health check on the connection"""
        pass
    
    # Helper methods
    
    async def _handle_connection_error(self, error: Exception):
        """Handle connection errors with retry logic"""
        logger.warning("Connection error, attempting recovery",
                      name=self.name,
                      error=str(error))
        
        self.status = ConnectorStatus.RECONNECTING
        
        for attempt in range(self.max_retries):
            try:
                await asyncio.sleep(self.retry_delay * (attempt + 1))  # Exponential backoff
                
                await self._close_connection()
                await self._initialize_connection()
                
                self.status = ConnectorStatus.RUNNING
                logger.info("Connection recovered successfully",
                           name=self.name,
                           attempt=attempt + 1)
                return
                
            except Exception as retry_error:
                logger.warning("Retry attempt failed",
                              name=self.name,
                              attempt=attempt + 1,
                              error=str(retry_error))
        
        # All retries failed
        self.status = ConnectorStatus.ERROR
        logger.error("Connection recovery failed after all retries",
                    name=self.name,
                    max_retries=self.max_retries)
    
    async def _health_check_loop(self):
        """Periodic health check loop"""
        while self._running:
            try:
                await asyncio.sleep(self.health_check_interval)
                
                if not self._running:
                    break
                
                is_healthy = await self._health_check()
                
                if not is_healthy and self.status == ConnectorStatus.RUNNING:
                    logger.warning("Health check failed", name=self.name)
                    # Trigger reconnection
                    await self._handle_connection_error(Exception("Health check failed"))
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Health check error", name=self.name, error=str(e))
    
    def _update_rate_metrics(self):
        """Update rate-based metrics"""
        now = datetime.now(timezone.utc)
        time_diff = (now - self._last_metrics_time).total_seconds()
        
        if time_diff >= 1.0:  # Update every second
            # Calculate alerts per second over the last interval
            alerts_in_interval = max(1, self.metrics.total_alerts)  # Avoid division by zero
            total_seconds = (now - self._connection_start_time).total_seconds() if self._connection_start_time else 1
            
            self.metrics.alerts_per_second = alerts_in_interval / max(total_seconds, 1)
            self._last_metrics_time = now
    
    def _validate_config(self, required_fields: List[str]):
        """Validate that required configuration fields are present"""
        missing_fields = []
        for field in required_fields:
            if field not in self.config or self.config[field] is None:
                missing_fields.append(field)
        
        if missing_fields:
            raise ValueError(f"Missing required configuration fields: {missing_fields}")
    
    async def _with_retries(self, operation, *args, **kwargs):
        """Execute an operation with retry logic"""
        last_exception = None
        
        for attempt in range(self.max_retries):
            try:
                return await operation(*args, **kwargs)
            except Exception as e:
                last_exception = e
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(self.retry_delay * (attempt + 1))
                    logger.warning("Operation failed, retrying",
                                  name=self.name,
                                  operation=operation.__name__,
                                  attempt=attempt + 1,
                                  error=str(e))
        
        # All retries failed
        raise last_exception
    
    def _format_alert_timestamp(self, timestamp: Any) -> str:
        """Format various timestamp formats to ISO string"""
        if isinstance(timestamp, datetime):
            return timestamp.isoformat()
        elif isinstance(timestamp, (int, float)):
            if timestamp > 1e10:  # Milliseconds
                timestamp = timestamp / 1000
            return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()
        elif isinstance(timestamp, str):
            # Already a string, validate and return
            try:
                datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                return timestamp
            except ValueError:
                return datetime.now(timezone.utc).isoformat()
        else:
            return datetime.now(timezone.utc).isoformat()
    
    async def _buffer_alert(self, alert: Dict[str, Any]):
        """Add alert to internal buffer with backpressure handling"""
        try:
            await asyncio.wait_for(
                self._alert_buffer.put(alert),
                timeout=1.0
            )
        except asyncio.TimeoutError:
            logger.warning("Alert buffer full, dropping alert",
                          name=self.name,
                          buffer_size=self.buffer_size)
            # Implement backpressure strategy here
            # Could pause fetching, increase processing, or alert operators
    
    async def _get_buffered_alerts(self, max_count: int = None) -> List[Dict[str, Any]]:
        """Get buffered alerts in batches"""
        alerts = []
        max_count = max_count or self.batch_size
        
        try:
            while len(alerts) < max_count:
                alert = await asyncio.wait_for(
                    self._alert_buffer.get(),
                    timeout=0.1
                )
                alerts.append(alert)
        except asyncio.TimeoutError:
            pass  # Normal timeout, return what we have
        
        return alerts