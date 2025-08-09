"""
IBM QRadar SIEM Connector

Production-grade integration with IBM QRadar SIEM providing
event ingestion, search capabilities, offense management, and real-time monitoring.
"""

import asyncio
import logging
import json
import base64
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, AsyncGenerator
from urllib.parse import urlencode, quote
import aiohttp

from .base_connector import (
    BaseSiemConnector, SiemConfig, SiemEvent, SiemResponse,
    SiemPlatform, EventSeverity, ConnectionStatus
)

logger = logging.getLogger(__name__)

class QRadarConfig(SiemConfig):
    """QRadar-specific configuration"""
    
    def __init__(
        self,
        host: str,
        port: int = 443,
        sec_token: str = "",
        username: str = "",
        password: str = "",
        api_version: str = "17.0",
        console_ip: Optional[str] = None,
        range_header: str = "items=0-49",  # Default pagination
        **kwargs
    ):
        super().__init__(
            platform=SiemPlatform.QRADAR,
            host=host,
            port=port,
            username=username,
            password=password,
            ssl_verify=kwargs.get('ssl_verify', True),
            **kwargs
        )
        self.sec_token = sec_token
        self.api_version = api_version
        self.console_ip = console_ip or host
        self.range_header = range_header

class QRadarConnector(BaseSiemConnector):
    """
    IBM QRadar SIEM connector with comprehensive REST API integration
    
    Supports:
    - SEC Token or Basic authentication
    - Event and flow ingestion via API
    - AQL (Ariel Query Language) searches
    - Offense management
    - Real-time event streaming
    - Custom log sources and DSM management
    """
    
    def __init__(self, config: QRadarConfig):
        super().__init__(config)
        self.config: QRadarConfig = config
        self._log_source_id: Optional[int] = None
        self._offenses_cache: Dict[int, Dict] = {}
        self._event_types: Dict[int, str] = {}
        
    def _get_base_url(self) -> str:
        """Get QRadar API base URL"""
        protocol = "https" if self.config.ssl_verify else "http"
        return f"{protocol}://{self.config.host}/api"
    
    def _get_auth_headers(self) -> Dict[str, str]:
        """Get QRadar authentication headers"""
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Version": self.config.api_version
        }
        
        if self.config.sec_token:
            headers["SEC"] = self.config.decrypt_credential(self.config.sec_token)
        elif self.config.username and self.config.password:
            # Basic authentication
            credentials = f"{self.config.decrypt_credential(self.config.username)}:{self.config.decrypt_credential(self.config.password)}"
            encoded_credentials = base64.b64encode(credentials.encode()).decode()
            headers["Authorization"] = f"Basic {encoded_credentials}"
            
        return headers
    
    async def connect(self) -> bool:
        """Connect to QRadar instance"""
        try:
            self._connection_status = ConnectionStatus.CONNECTING
            
            # Create session with connection pooling
            connector = aiohttp.TCPConnector(
                limit=self.config.connection_pool_size,
                ssl=self._ssl_context
            )
            self._session = aiohttp.ClientSession(connector=connector)
            
            # Authenticate and validate connection
            if await self.authenticate():
                # Setup log source for event ingestion
                await self._setup_log_source()
                
                self._connection_status = ConnectionStatus.CONNECTED
                self._last_heartbeat = datetime.utcnow()
                logger.info(f"Connected to QRadar at {self.config.host}")
                return True
            else:
                self._connection_status = ConnectionStatus.AUTHENTICATION_FAILED
                return False
                
        except Exception as e:
            logger.error(f"Failed to connect to QRadar: {e}")
            self._connection_status = ConnectionStatus.ERROR
            return False
    
    async def disconnect(self) -> bool:
        """Disconnect from QRadar"""
        try:
            if self._session:
                await self._session.close()
                self._session = None
            
            self._connection_status = ConnectionStatus.DISCONNECTED
            logger.info("Disconnected from QRadar")
            return True
            
        except Exception as e:
            logger.error(f"Error disconnecting from QRadar: {e}")
            return False
    
    async def authenticate(self) -> bool:
        """Authenticate with QRadar"""
        try:
            # Test authentication by getting system info
            response = await self._make_api_call("GET", "/system/about")
            
            if response.is_success():
                logger.info("QRadar authentication successful")
                return True
            else:
                logger.error(f"QRadar authentication failed: {response.message}")
                return False
                
        except Exception as e:
            logger.error(f"QRadar authentication error: {e}")
            return False
    
    async def _setup_log_source(self) -> bool:
        """Setup or find isectech log source"""
        try:
            # Check if isectech log source exists
            response = await self._make_api_call(
                "GET", 
                "/config/event_sources/log_source_management/log_sources",
                params={"filter": "name='isectech-ai-ml'"}
            )
            
            if response.is_success() and response.data:
                sources = response.data
                if sources:
                    self._log_source_id = sources[0]['id']
                    logger.info(f"Found existing isectech log source: {self._log_source_id}")
                    return True
            
            # Create new log source
            log_source_data = {
                "name": "isectech-ai-ml",
                "description": "isectech AI/ML Threat Detection Events",
                "type_id": 1,  # Syslog
                "protocol_type_id": 0,  # Syslog
                "enabled": True,
                "gateway": False,
                "internal": False,
                "credibility": 5,
                "target_event_collector_id": 1
            }
            
            response = await self._make_api_call(
                "POST",
                "/config/event_sources/log_source_management/log_sources",
                data=log_source_data
            )
            
            if response.is_success() and response.data:
                self._log_source_id = response.data['id']
                logger.info(f"Created isectech log source: {self._log_source_id}")
                return True
            
            logger.warning("Failed to setup QRadar log source")
            return False
            
        except Exception as e:
            logger.error(f"Error setting up QRadar log source: {e}")
            return False
    
    async def send_event(self, event: SiemEvent) -> SiemResponse:
        """Send event to QRadar"""
        try:
            # Convert event to QRadar format
            qradar_event = await self._convert_to_qradar_event(event)
            
            # Send event via log source
            response = await self._make_api_call(
                "POST",
                "/data_collection/events",
                data=qradar_event
            )
            
            if response.is_success():
                self._metrics['events_sent'] += 1
            
            return response
            
        except Exception as e:
            logger.error(f"Failed to send event to QRadar: {e}")
            return SiemResponse(
                success=False,
                status_code=500,
                message=f"Failed to send event: {e}",
                error_details=str(e)
            )
    
    async def _convert_to_qradar_event(self, event: SiemEvent) -> Dict[str, Any]:
        """Convert SiemEvent to QRadar event format"""
        severity_mapping = {
            EventSeverity.CRITICAL: 10,
            EventSeverity.HIGH: 8,
            EventSeverity.MEDIUM: 5,
            EventSeverity.LOW: 3,
            EventSeverity.INFO: 1
        }
        
        qradar_event = {
            "events": [{
                "log_source_id": self._log_source_id,
                "start_time": int(event.timestamp.timestamp() * 1000),  # Milliseconds
                "end_time": int(event.timestamp.timestamp() * 1000),
                "severity": severity_mapping.get(event.severity, 5),
                "category_id": await self._get_or_create_category(event.category),
                "qid": await self._get_or_create_event_type(event.event_type),
                "source_ip": event.source_ip,
                "destination_ip": event.destination_ip,
                "username": event.user_id,
                "payload": json.dumps({
                    "id": event.id,
                    "message": event.message,
                    "source": event.source,
                    "tags": event.tags,
                    "metadata": event.metadata,
                    **event.raw_data
                }),
                "properties": self._build_event_properties(event)
            }]
        }
        
        return qradar_event
    
    async def _get_or_create_category(self, category: str) -> int:
        """Get or create QRadar event category"""
        try:
            # Check existing categories
            response = await self._make_api_call(
                "GET",
                "/data_collection/event_categories",
                params={"filter": f"name='{category}'"}
            )
            
            if response.is_success() and response.data:
                categories = response.data
                if categories:
                    return categories[0]['id']
            
            # Create new category (if allowed by QRadar configuration)
            category_data = {
                "name": category,
                "description": f"isectech {category} events"
            }
            
            response = await self._make_api_call(
                "POST",
                "/data_collection/event_categories",
                data=category_data
            )
            
            if response.is_success() and response.data:
                return response.data['id']
                
            # Default to unknown category if creation fails
            return 1000  # Default unknown category
            
        except Exception as e:
            logger.warning(f"Error managing QRadar category: {e}")
            return 1000
    
    async def _get_or_create_event_type(self, event_type: str) -> int:
        """Get or create QRadar QID for event type"""
        # For simplicity, use a hash-based approach to generate consistent QIDs
        # In production, you would manage this through QRadar's DSM
        qid = hash(event_type) % 900000 + 100000  # Range: 100000-999999
        self._event_types[qid] = event_type
        return qid
    
    def _build_event_properties(self, event: SiemEvent) -> List[Dict[str, Any]]:
        """Build QRadar event properties"""
        properties = []
        
        # Add standard properties
        if event.asset_id:
            properties.append({
                "property_id": 1,  # Asset ID
                "value": event.asset_id
            })
        
        # Add custom properties from metadata
        for key, value in event.metadata.items():
            if isinstance(value, (str, int, float)):
                properties.append({
                    "property_id": hash(key) % 1000 + 2000,  # Custom property range
                    "value": str(value)
                })
        
        return properties
    
    async def query_events(
        self,
        query: str,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 1000
    ) -> List[SiemEvent]:
        """Query events using AQL (Ariel Query Language)"""
        try:
            # Build AQL query
            aql_query = query
            
            # Add time constraints if provided
            if start_time and end_time:
                start_ms = int(start_time.timestamp() * 1000)
                end_ms = int(end_time.timestamp() * 1000)
                time_filter = f" WHERE starttime >= {start_ms} AND starttime <= {end_ms}"
                
                if "WHERE" in aql_query.upper():
                    aql_query = aql_query.replace(" WHERE ", f" WHERE starttime >= {start_ms} AND starttime <= {end_ms} AND ")
                else:
                    aql_query += time_filter
            
            # Add limit
            aql_query += f" LAST {limit} SECONDS"
            
            # Execute search
            search_data = {
                "query_expression": aql_query
            }
            
            response = await self._make_api_call(
                "POST",
                "/ariel/searches",
                data=search_data
            )
            
            if not response.is_success():
                logger.error(f"QRadar search failed: {response.message}")
                return []
            
            search_id = response.data.get('search_id')
            if not search_id:
                logger.error("No search ID returned from QRadar")
                return []
            
            # Wait for search completion
            events = await self._wait_for_search_results(search_id, limit)
            return events
            
        except Exception as e:
            logger.error(f"Failed to query QRadar events: {e}")
            return []
    
    async def _wait_for_search_results(self, search_id: str, limit: int) -> List[SiemEvent]:
        """Wait for AQL search completion and retrieve results"""
        max_wait_time = 300  # 5 minutes
        start_time = datetime.utcnow()
        
        while (datetime.utcnow() - start_time).total_seconds() < max_wait_time:
            # Check search status
            response = await self._make_api_call(
                "GET",
                f"/ariel/searches/{search_id}"
            )
            
            if response.is_success() and response.data:
                status = response.data.get('status')
                
                if status == 'COMPLETED':
                    # Get results
                    results_response = await self._make_api_call(
                        "GET",
                        f"/ariel/searches/{search_id}/results",
                        headers={"Range": f"items=0-{limit-1}"}
                    )
                    
                    if results_response.is_success() and results_response.data:
                        return await self._parse_qradar_results(results_response.data)
                    
                elif status == 'ERROR':
                    logger.error("QRadar search failed with error")
                    break
            
            await asyncio.sleep(2)
        
        logger.warning(f"QRadar search {search_id} timed out")
        return []
    
    async def _parse_qradar_results(self, results: Dict[str, Any]) -> List[SiemEvent]:
        """Parse QRadar search results into SiemEvent objects"""
        events = []
        
        for event_data in results.get('events', []):
            try:
                # Parse payload
                payload = {}
                if event_data.get('payload'):
                    try:
                        payload = json.loads(event_data['payload'])
                    except json.JSONDecodeError:
                        payload = {"raw_payload": event_data['payload']}
                
                # Map QRadar severity to EventSeverity
                qradar_severity = event_data.get('magnitude', 5)
                if qradar_severity >= 9:
                    severity = EventSeverity.CRITICAL
                elif qradar_severity >= 7:
                    severity = EventSeverity.HIGH
                elif qradar_severity >= 4:
                    severity = EventSeverity.MEDIUM
                elif qradar_severity >= 2:
                    severity = EventSeverity.LOW
                else:
                    severity = EventSeverity.INFO
                
                event = SiemEvent(
                    id=payload.get('id', str(event_data.get('qidname_qid', ''))),
                    timestamp=datetime.fromtimestamp(event_data.get('starttime', 0) / 1000),
                    source=payload.get('source', 'qradar'),
                    event_type=self._event_types.get(event_data.get('qid'), 'unknown'),
                    severity=severity,
                    category=event_data.get('categoryname', 'security'),
                    message=payload.get('message', event_data.get('eventdirection', '')),
                    source_ip=event_data.get('sourceip'),
                    destination_ip=event_data.get('destinationip'),
                    user_id=event_data.get('username'),
                    tags=payload.get('tags', []),
                    metadata=payload.get('metadata', {}),
                    raw_data=event_data
                )
                
                events.append(event)
                
            except Exception as e:
                logger.warning(f"Failed to parse QRadar event: {e}")
                continue
        
        return events
    
    async def create_alert(
        self,
        title: str,
        description: str,
        severity: EventSeverity = EventSeverity.MEDIUM,
        metadata: Optional[Dict[str, Any]] = None
    ) -> SiemResponse:
        """Create offense in QRadar"""
        try:
            # Create custom offense (requires specific QRadar configuration)
            offense_data = {
                "description": f"{title}: {description}",
                "severity": self._map_severity_to_qradar(severity),
                "relevance": 5,
                "credibility": 5,
                "source_network": "isectech-ai-ml",
                "destination_networks": ["unknown"],
                "categories": ["Suspicious Activity"],
                "closing_reason_id": None  # Keep open
            }
            
            # Note: Creating offenses directly via API is limited in QRadar
            # Alternative: Create event that triggers offense rules
            alert_event = SiemEvent(
                id=f"alert_{datetime.utcnow().timestamp()}",
                source="isectech-ai-ml",
                event_type="security_alert",
                severity=severity,
                category="alert",
                message=f"{title}: {description}",
                metadata=metadata or {}
            )
            
            return await self.send_event(alert_event)
            
        except Exception as e:
            logger.error(f"Failed to create QRadar alert: {e}")
            return SiemResponse(
                success=False,
                status_code=500,
                message=f"Failed to create alert: {e}",
                error_details=str(e)
            )
    
    def _map_severity_to_qradar(self, severity: EventSeverity) -> int:
        """Map EventSeverity to QRadar severity scale"""
        mapping = {
            EventSeverity.CRITICAL: 10,
            EventSeverity.HIGH: 8,
            EventSeverity.MEDIUM: 5,
            EventSeverity.LOW: 3,
            EventSeverity.INFO: 1
        }
        return mapping.get(severity, 5)
    
    async def _stream_events(self) -> AsyncGenerator[SiemEvent, None]:
        """Stream real-time events from QRadar"""
        try:
            # Use polling approach for QRadar event streaming
            last_poll_time = datetime.utcnow() - timedelta(minutes=1)
            
            while self._connection_status == ConnectionStatus.CONNECTED:
                try:
                    # Query recent events
                    current_time = datetime.utcnow()
                    start_ms = int(last_poll_time.timestamp() * 1000)
                    end_ms = int(current_time.timestamp() * 1000)
                    
                    aql_query = f"""
                    SELECT starttime, qid, qidname_qid, sourceip, destinationip, username,
                           magnitude, categoryname, payload, eventdirection
                    FROM events
                    WHERE starttime >= {start_ms} AND starttime <= {end_ms}
                    AND (qidname_qid ILIKE '%isectech%' OR payload ILIKE '%isectech%')
                    LAST 5 MINUTES
                    """
                    
                    events = await self.query_events(aql_query, last_poll_time, current_time, 100)
                    
                    for event in events:
                        self._metrics['events_received'] += 1
                        self._metrics['last_activity'] = datetime.utcnow()
                        yield event
                    
                    last_poll_time = current_time
                    await asyncio.sleep(30)  # Poll every 30 seconds
                    
                except Exception as e:
                    logger.error(f"Error in QRadar event streaming: {e}")
                    await asyncio.sleep(60)  # Wait longer on error
                    
        except Exception as e:
            logger.error(f"Failed to start QRadar event stream: {e}")
    
    async def get_offenses(
        self,
        limit: int = 50,
        status: Optional[str] = "OPEN"
    ) -> List[Dict[str, Any]]:
        """Get QRadar offenses"""
        try:
            params = {"Range": f"items=0-{limit-1}"}
            if status:
                params["filter"] = f"status='{status}'"
                
            response = await self._make_api_call(
                "GET",
                "/siem/offenses",
                params=params
            )
            
            if response.is_success() and response.data:
                offenses = response.data
                # Cache offenses
                for offense in offenses:
                    self._offenses_cache[offense['id']] = offense
                return offenses
            
            return []
            
        except Exception as e:
            logger.error(f"Failed to get QRadar offenses: {e}")
            return []
    
    async def close_offense(self, offense_id: int, closing_reason: str = "Non-Issue") -> bool:
        """Close a QRadar offense"""
        try:
            # Get closing reason ID
            reasons_response = await self._make_api_call(
                "GET",
                "/siem/offense_closing_reasons"
            )
            
            closing_reason_id = 1  # Default
            if reasons_response.is_success() and reasons_response.data:
                for reason in reasons_response.data:
                    if reason['text'] == closing_reason:
                        closing_reason_id = reason['id']
                        break
            
            # Close offense
            close_data = {
                "closing_reason_id": closing_reason_id,
                "status": "CLOSED"
            }
            
            response = await self._make_api_call(
                "POST",
                f"/siem/offenses/{offense_id}",
                data=close_data
            )
            
            return response.is_success()
            
        except Exception as e:
            logger.error(f"Failed to close QRadar offense {offense_id}: {e}")
            return False