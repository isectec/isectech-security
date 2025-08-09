"""
Splunk SIEM Connector

Production-grade integration with Splunk Enterprise and Splunk Cloud
providing real-time event ingestion, search capabilities, and alert management.
"""

import asyncio
import logging
import json
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, AsyncGenerator
from urllib.parse import urlencode
import aiohttp

from .base_connector import (
    BaseSiemConnector, SiemConfig, SiemEvent, SiemResponse,
    SiemPlatform, EventSeverity, ConnectionStatus
)

logger = logging.getLogger(__name__)

class SplunkConfig(SiemConfig):
    """Splunk-specific configuration"""
    
    def __init__(
        self,
        host: str,
        port: int = 8089,
        username: str = "",
        password: str = "",
        token: str = "",
        management_port: int = 8089,
        web_port: int = 8000,
        app: str = "search",
        owner: str = "admin",
        ssl_verify: bool = True,
        **kwargs
    ):
        super().__init__(
            platform=SiemPlatform.SPLUNK,
            host=host,
            port=port,
            username=username,
            password=password,
            token=token,
            ssl_verify=ssl_verify,
            **kwargs
        )
        self.management_port = management_port
        self.web_port = web_port
        self.app = app
        self.owner = owner

class SplunkConnector(BaseSiemConnector):
    """
    Splunk SIEM connector with full REST API integration
    
    Supports:
    - Authentication via username/password or token
    - Real-time event ingestion via HTTP Event Collector (HEC)
    - Search and query capabilities
    - Alert creation and management
    - Real-time search streaming
    """
    
    def __init__(self, config: SplunkConfig):
        super().__init__(config)
        self.config: SplunkConfig = config
        self._session_key: Optional[str] = None
        self._hec_token: Optional[str] = None
        self._search_jobs: Dict[str, str] = {}
        
    def _get_base_url(self) -> str:
        """Get Splunk management base URL"""
        protocol = "https" if self.config.ssl_verify else "http"
        return f"{protocol}://{self.config.host}:{self.config.management_port}"
    
    def _get_hec_url(self) -> str:
        """Get HTTP Event Collector URL"""
        protocol = "https" if self.config.ssl_verify else "http"
        return f"{protocol}://{self.config.host}:{self.config.port}/services/collector/event"
    
    def _get_auth_headers(self) -> Dict[str, str]:
        """Get Splunk authentication headers"""
        if self.config.token:
            return {"Authorization": f"Bearer {self.config.token}"}
        elif self._session_key:
            return {"Authorization": f"Splunk {self._session_key}"}
        else:
            return {}
    
    async def connect(self) -> bool:
        """Connect to Splunk instance"""
        try:
            self._connection_status = ConnectionStatus.CONNECTING
            
            # Create session with connection pooling
            connector = aiohttp.TCPConnector(
                limit=self.config.connection_pool_size,
                ssl=self._ssl_context
            )
            self._session = aiohttp.ClientSession(connector=connector)
            
            # Authenticate
            if await self.authenticate():
                self._connection_status = ConnectionStatus.CONNECTED
                self._last_heartbeat = datetime.utcnow()
                logger.info(f"Connected to Splunk at {self.config.host}")
                return True
            else:
                self._connection_status = ConnectionStatus.AUTHENTICATION_FAILED
                return False
                
        except Exception as e:
            logger.error(f"Failed to connect to Splunk: {e}")
            self._connection_status = ConnectionStatus.ERROR
            return False
    
    async def disconnect(self) -> bool:
        """Disconnect from Splunk"""
        try:
            if self._session:
                await self._session.close()
                self._session = None
            
            self._session_key = None
            self._connection_status = ConnectionStatus.DISCONNECTED
            logger.info("Disconnected from Splunk")
            return True
            
        except Exception as e:
            logger.error(f"Error disconnecting from Splunk: {e}")
            return False
    
    async def authenticate(self) -> bool:
        """Authenticate with Splunk"""
        try:
            # If using token authentication, verify token
            if self.config.token:
                response = await self._make_api_call("GET", "/services/authentication/current-context")
                return response.is_success()
            
            # Username/password authentication
            elif self.config.username and self.config.password:
                auth_data = {
                    "username": self.config.decrypt_credential(self.config.username),
                    "password": self.config.decrypt_credential(self.config.password)
                }
                
                response = await self._make_api_call(
                    "POST", 
                    "/services/auth/login",
                    data=auth_data,
                    headers={"Content-Type": "application/x-www-form-urlencoded"}
                )
                
                if response.is_success() and response.data:
                    # Parse session key from XML response
                    try:
                        root = ET.fromstring(response.data.get('text', ''))
                        session_key_elem = root.find('.//sessionKey')
                        if session_key_elem is not None:
                            self._session_key = session_key_elem.text
                            logger.info("Splunk authentication successful")
                            return True
                    except ET.ParseError:
                        logger.error("Failed to parse Splunk authentication response")
                
                return False
            
            else:
                logger.error("No valid Splunk authentication credentials provided")
                return False
                
        except Exception as e:
            logger.error(f"Splunk authentication failed: {e}")
            return False
    
    async def send_event(self, event: SiemEvent) -> SiemResponse:
        """Send event to Splunk via HTTP Event Collector or API"""
        try:
            # Prefer HEC if token available
            if self.config.token or self._hec_token:
                return await self._send_event_hec(event)
            else:
                return await self._send_event_api(event)
                
        except Exception as e:
            logger.error(f"Failed to send event to Splunk: {e}")
            return SiemResponse(
                success=False,
                status_code=500,
                message=f"Failed to send event: {e}",
                error_details=str(e)
            )
    
    async def _send_event_hec(self, event: SiemEvent) -> SiemResponse:
        """Send event via HTTP Event Collector"""
        hec_event = {
            "time": event.timestamp.timestamp(),
            "source": event.source,
            "sourcetype": f"isectech:{event.event_type}",
            "index": "security",
            "event": {
                "id": event.id,
                "message": event.message,
                "severity": event.severity.name,
                "category": event.category,
                "source_ip": event.source_ip,
                "destination_ip": event.destination_ip,
                "user_id": event.user_id,
                "asset_id": event.asset_id,
                "tags": event.tags,
                "metadata": event.metadata,
                **event.raw_data
            }
        }
        
        headers = {
            "Authorization": f"Splunk {self.config.token or self._hec_token}",
            "Content-Type": "application/json"
        }
        
        async with self._session.post(
            self._get_hec_url(),
            json=hec_event,
            headers=headers,
            ssl=self._ssl_context
        ) as response:
            
            response_data = await response.json() if response.content_type == 'application/json' else {"text": await response.text()}
            
            self._metrics['events_sent'] += 1
            
            return SiemResponse(
                success=response.status == 200,
                status_code=response.status,
                message="Event sent via HEC",
                data=response_data
            )
    
    async def _send_event_api(self, event: SiemEvent) -> SiemResponse:
        """Send event via Splunk REST API"""
        search_command = f"""
        | makeresults 
        | eval 
            id="{event.id}",
            timestamp="{event.timestamp.isoformat()}",
            source="{event.source}",
            event_type="{event.event_type}",
            severity="{event.severity.name}",
            category="{event.category}",
            message="{event.message}",
            source_ip="{event.source_ip or ''}",
            destination_ip="{event.destination_ip or ''}",
            user_id="{event.user_id or ''}",
            asset_id="{event.asset_id or ''}",
            tags="{','.join(event.tags)}"
        | collect index=security sourcetype="isectech:threat_event"
        """
        
        return await self._execute_search(search_command)
    
    async def query_events(
        self,
        query: str,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 1000
    ) -> List[SiemEvent]:
        """Query events from Splunk"""
        try:
            # Build search query
            search_query = query
            
            if start_time and end_time:
                earliest = start_time.strftime("%Y-%m-%dT%H:%M:%S.%f")
                latest = end_time.strftime("%Y-%m-%dT%H:%M:%S.%f")
                search_query += f" earliest={earliest} latest={latest}"
            
            search_query += f" | head {limit}"
            
            # Execute search
            response = await self._execute_search(search_query, wait_for_completion=True)
            
            if not response.is_success():
                logger.error(f"Splunk search failed: {response.message}")
                return []
            
            # Parse results
            events = []
            results = response.data.get('results', [])
            
            for result in results:
                try:
                    event = SiemEvent(
                        id=result.get('id', ''),
                        timestamp=datetime.fromisoformat(result.get('timestamp', datetime.utcnow().isoformat())),
                        source=result.get('source', 'splunk'),
                        event_type=result.get('event_type', 'unknown'),
                        severity=EventSeverity[result.get('severity', 'MEDIUM')],
                        category=result.get('category', 'security'),
                        message=result.get('message', ''),
                        source_ip=result.get('source_ip'),
                        destination_ip=result.get('destination_ip'),
                        user_id=result.get('user_id'),
                        asset_id=result.get('asset_id'),
                        tags=result.get('tags', '').split(',') if result.get('tags') else [],
                        raw_data=result
                    )
                    events.append(event)
                    
                except Exception as e:
                    logger.warning(f"Failed to parse Splunk event: {e}")
                    continue
            
            return events
            
        except Exception as e:
            logger.error(f"Failed to query Splunk events: {e}")
            return []
    
    async def create_alert(
        self,
        title: str,
        description: str,
        severity: EventSeverity = EventSeverity.MEDIUM,
        metadata: Optional[Dict[str, Any]] = None
    ) -> SiemResponse:
        """Create alert in Splunk"""
        try:
            # Create saved search as alert
            alert_data = {
                "name": f"isectech_alert_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}",
                "search": f"""
                    | makeresults 
                    | eval 
                        title="{title}",
                        description="{description}",
                        severity="{severity.name}",
                        created=now(),
                        metadata="{json.dumps(metadata or {})}"
                    | collect index=security sourcetype="isectech:alert"
                """,
                "is_scheduled": "1",
                "cron_schedule": "* * * * *",
                "actions": "email",
                "action.email.to": "security-team@isectech.com",
                "action.email.subject": f"Security Alert: {title}",
                "action.email.message.alert": description
            }
            
            return await self._make_api_call(
                "POST",
                f"/servicesNS/{self.config.owner}/{self.config.app}/saved/searches",
                data=alert_data
            )
            
        except Exception as e:
            logger.error(f"Failed to create Splunk alert: {e}")
            return SiemResponse(
                success=False,
                status_code=500,
                message=f"Failed to create alert: {e}",
                error_details=str(e)
            )
    
    async def _execute_search(
        self, 
        search_query: str, 
        wait_for_completion: bool = False,
        timeout: int = 300
    ) -> SiemResponse:
        """Execute Splunk search"""
        try:
            # Start search job
            search_data = {
                "search": f"search {search_query}",
                "output_mode": "json",
                "earliest_time": "-24h",
                "latest_time": "now"
            }
            
            response = await self._make_api_call(
                "POST",
                f"/servicesNS/{self.config.owner}/{self.config.app}/search/jobs",
                data=search_data
            )
            
            if not response.is_success():
                return response
            
            # Extract job SID
            job_sid = response.data.get('sid')
            if not job_sid:
                return SiemResponse(
                    success=False,
                    status_code=500,
                    message="Failed to get search job SID"
                )
            
            self._search_jobs[search_query] = job_sid
            
            if wait_for_completion:
                # Wait for job completion
                start_time = datetime.utcnow()
                while (datetime.utcnow() - start_time).total_seconds() < timeout:
                    job_status = await self._make_api_call(
                        "GET",
                        f"/servicesNS/{self.config.owner}/{self.config.app}/search/jobs/{job_sid}"
                    )
                    
                    if job_status.is_success() and job_status.data:
                        state = job_status.data.get('entry', [{}])[0].get('content', {}).get('dispatchState')
                        if state == 'DONE':
                            # Get results
                            results_response = await self._make_api_call(
                                "GET",
                                f"/servicesNS/{self.config.owner}/{self.config.app}/search/jobs/{job_sid}/results",
                                params={"output_mode": "json", "count": 0}
                            )
                            return results_response
                        elif state == 'FAILED':
                            return SiemResponse(
                                success=False,
                                status_code=500,
                                message="Search job failed"
                            )
                    
                    await asyncio.sleep(1)
                
                return SiemResponse(
                    success=False,
                    status_code=408,
                    message="Search job timeout"
                )
            
            return response
            
        except Exception as e:
            logger.error(f"Failed to execute Splunk search: {e}")
            return SiemResponse(
                success=False,
                status_code=500,
                message=f"Search execution failed: {e}",
                error_details=str(e)
            )
    
    async def _stream_events(self) -> AsyncGenerator[SiemEvent, None]:
        """Stream real-time events from Splunk"""
        try:
            # Create real-time search
            search_query = """
            search index=security sourcetype="isectech:*" 
            | eval event_timestamp=_time
            | sort -_time
            """
            
            # Start real-time search
            search_data = {
                "search": search_query,
                "search_mode": "realtime",
                "earliest_time": "rt-5m",
                "latest_time": "rt",
                "output_mode": "json"
            }
            
            response = await self._make_api_call(
                "POST",
                f"/servicesNS/{self.config.owner}/{self.config.app}/search/jobs",
                data=search_data
            )
            
            if not response.is_success():
                logger.error("Failed to start real-time search")
                return
            
            job_sid = response.data.get('sid')
            if not job_sid:
                logger.error("No job SID received for real-time search")
                return
            
            # Stream results
            while self._connection_status == ConnectionStatus.CONNECTED:
                try:
                    results_response = await self._make_api_call(
                        "GET",
                        f"/servicesNS/{self.config.owner}/{self.config.app}/search/jobs/{job_sid}/results_preview",
                        params={"output_mode": "json", "count": 100}
                    )
                    
                    if results_response.is_success() and results_response.data:
                        results = results_response.data.get('results', [])
                        
                        for result in results:
                            try:
                                event = SiemEvent(
                                    id=result.get('id', f"splunk_{datetime.utcnow().timestamp()}"),
                                    timestamp=datetime.fromtimestamp(float(result.get('event_timestamp', datetime.utcnow().timestamp()))),
                                    source=result.get('source', 'splunk'),
                                    event_type=result.get('sourcetype', '').replace('isectech:', ''),
                                    severity=EventSeverity[result.get('severity', 'MEDIUM')],
                                    category=result.get('category', 'security'),
                                    message=result.get('message', result.get('_raw', '')),
                                    source_ip=result.get('source_ip'),
                                    destination_ip=result.get('destination_ip'),
                                    user_id=result.get('user_id'),
                                    asset_id=result.get('asset_id'),
                                    raw_data=result
                                )
                                yield event
                                
                            except Exception as e:
                                logger.warning(f"Failed to parse streaming event: {e}")
                                continue
                    
                    await asyncio.sleep(5)  # Poll every 5 seconds
                    
                except Exception as e:
                    logger.error(f"Error in event streaming: {e}")
                    await asyncio.sleep(10)
                    break
                    
        except Exception as e:
            logger.error(f"Failed to start event stream: {e}")
    
    def get_search_jobs(self) -> Dict[str, str]:
        """Get active search jobs"""
        return self._search_jobs.copy()
    
    async def cancel_search_job(self, job_sid: str) -> bool:
        """Cancel a search job"""
        try:
            response = await self._make_api_call(
                "POST",
                f"/servicesNS/{self.config.owner}/{self.config.app}/search/jobs/{job_sid}/control",
                data={"action": "cancel"}
            )
            return response.is_success()
        except Exception as e:
            logger.error(f"Failed to cancel search job {job_sid}: {e}")
            return False