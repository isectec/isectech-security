"""
Microsoft Sentinel SIEM Connector

Production-grade integration with Microsoft Sentinel (Azure Sentinel) providing
event ingestion, KQL queries, incident management, and real-time monitoring.
"""

import asyncio
import logging
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, AsyncGenerator
from urllib.parse import quote
import aiohttp
from azure.identity import ClientSecretCredential, DefaultAzureCredential
from azure.core.credentials import AccessToken

from .base_connector import (
    BaseSiemConnector, SiemConfig, SiemEvent, SiemResponse,
    SiemPlatform, EventSeverity, ConnectionStatus
)

logger = logging.getLogger(__name__)

class SentinelConfig(SiemConfig):
    """Microsoft Sentinel-specific configuration"""
    
    def __init__(
        self,
        workspace_id: str,
        subscription_id: str,
        resource_group: str,
        tenant_id: str,
        client_id: str = "",
        client_secret: str = "",
        host: str = "management.azure.com",
        port: int = 443,
        api_version: str = "2023-02-01",
        **kwargs
    ):
        super().__init__(
            platform=SiemPlatform.SENTINEL,
            host=host,
            port=port,
            ssl_verify=kwargs.get('ssl_verify', True),
            **kwargs
        )
        self.workspace_id = workspace_id
        self.subscription_id = subscription_id
        self.resource_group = resource_group
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.api_version = api_version

class SentinelConnector(BaseSiemConnector):
    """
    Microsoft Sentinel connector with comprehensive REST API integration
    
    Supports:
    - Azure AD authentication with service principal or managed identity
    - Custom log ingestion via Data Collector API
    - KQL (Kusto Query Language) queries
    - Incident management
    - Watchlist and threat indicators
    - Real-time data streaming
    """
    
    def __init__(self, config: SentinelConfig):
        super().__init__(config)
        self.config: SentinelConfig = config
        self._credential: Optional[Any] = None
        self._access_token: Optional[str] = None
        self._token_expires: Optional[datetime] = None
        self._workspace_resource_url = (
            f"/subscriptions/{config.subscription_id}"
            f"/resourceGroups/{config.resource_group}"
            f"/providers/Microsoft.OperationalInsights"
            f"/workspaces/{config.workspace_id}"
        )
        
    def _get_base_url(self) -> str:
        """Get Sentinel management base URL"""
        return f"https://{self.config.host}"
    
    def _get_logs_base_url(self) -> str:
        """Get Azure Monitor Logs API base URL"""
        return f"https://api.loganalytics.io/v1/workspaces/{self.config.workspace_id}"
    
    def _get_data_collector_url(self) -> str:
        """Get Data Collector API URL for log ingestion"""
        return f"https://{self.config.workspace_id}.ods.opinsights.azure.com/api/logs"
    
    def _get_auth_headers(self) -> Dict[str, str]:
        """Get Sentinel authentication headers"""
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        
        if self._access_token:
            headers["Authorization"] = f"Bearer {self._access_token}"
            
        return headers
    
    async def connect(self) -> bool:
        """Connect to Microsoft Sentinel"""
        try:
            self._connection_status = ConnectionStatus.CONNECTING
            
            # Setup Azure credentials
            if self.config.client_id and self.config.client_secret:
                self._credential = ClientSecretCredential(
                    tenant_id=self.config.tenant_id,
                    client_id=self.config.decrypt_credential(self.config.client_id),
                    client_secret=self.config.decrypt_credential(self.config.client_secret)
                )
            else:
                # Use default Azure credential (managed identity, Azure CLI, etc.)
                self._credential = DefaultAzureCredential()
            
            # Create session
            connector = aiohttp.TCPConnector(
                limit=self.config.connection_pool_size,
                ssl=self._ssl_context
            )
            self._session = aiohttp.ClientSession(connector=connector)
            
            # Authenticate
            if await self.authenticate():
                self._connection_status = ConnectionStatus.CONNECTED
                self._last_heartbeat = datetime.utcnow()
                logger.info(f"Connected to Sentinel workspace {self.config.workspace_id}")
                return True
            else:
                self._connection_status = ConnectionStatus.AUTHENTICATION_FAILED
                return False
                
        except Exception as e:
            logger.error(f"Failed to connect to Sentinel: {e}")
            self._connection_status = ConnectionStatus.ERROR
            return False
    
    async def disconnect(self) -> bool:
        """Disconnect from Microsoft Sentinel"""
        try:
            if self._session:
                await self._session.close()
                self._session = None
            
            self._access_token = None
            self._token_expires = None
            self._connection_status = ConnectionStatus.DISCONNECTED
            logger.info("Disconnected from Sentinel")
            return True
            
        except Exception as e:
            logger.error(f"Error disconnecting from Sentinel: {e}")
            return False
    
    async def authenticate(self) -> bool:
        """Authenticate with Microsoft Sentinel using Azure AD"""
        try:
            # Get access token
            await self._refresh_access_token()
            
            if self._access_token:
                # Validate token by testing API access
                response = await self._make_api_call(
                    "GET",
                    f"{self._workspace_resource_url}",
                    params={"api-version": self.config.api_version}
                )
                
                if response.is_success():
                    logger.info("Sentinel authentication successful")
                    return True
                else:
                    logger.error(f"Sentinel authentication validation failed: {response.message}")
                    return False
            
            return False
            
        except Exception as e:
            logger.error(f"Sentinel authentication error: {e}")
            return False
    
    async def _refresh_access_token(self) -> None:
        """Refresh Azure AD access token"""
        try:
            # Check if token needs refresh
            if (self._access_token and self._token_expires and 
                datetime.utcnow() < self._token_expires - timedelta(minutes=5)):
                return
            
            # Get new token
            scope = "https://management.azure.com/.default"
            
            if hasattr(self._credential, 'get_token'):
                token: AccessToken = self._credential.get_token(scope)
                self._access_token = token.token
                self._token_expires = datetime.fromtimestamp(token.expires_on)
                logger.debug("Azure AD token refreshed")
            else:
                raise Exception("Invalid credential object")
                
        except Exception as e:
            logger.error(f"Failed to refresh Azure AD token: {e}")
            self._access_token = None
            self._token_expires = None
            raise
    
    async def send_event(self, event: SiemEvent) -> SiemResponse:
        """Send event to Sentinel via Data Collector API"""
        try:
            await self._refresh_access_token()
            
            # Convert event to Log Analytics format
            log_entry = {
                "TimeGenerated": event.timestamp.isoformat(),
                "EventId": event.id,
                "Source": event.source,
                "EventType": event.event_type,
                "Severity": event.severity.name,
                "Category": event.category,
                "Message": event.message,
                "SourceIP": event.source_ip or "",
                "DestinationIP": event.destination_ip or "",
                "UserId": event.user_id or "",
                "AssetId": event.asset_id or "",
                "Tags": ",".join(event.tags),
                "Metadata": json.dumps(event.metadata),
                "RawData": json.dumps(event.raw_data)
            }
            
            # Prepare request
            log_type = "isectech_threat_events"
            timestamp_field = "TimeGenerated"
            
            # Calculate signature for authentication
            import hmac
            import base64
            import hashlib
            
            body = json.dumps([log_entry])
            content_length = len(body.encode('utf-8'))
            
            # Note: For Data Collector API, you need workspace key
            # This is a simplified version - in production, implement proper HMAC-SHA256 signature
            
            headers = {
                "Content-Type": "application/json",
                "Log-Type": log_type,
                "time-generated-field": timestamp_field
            }
            
            async with self._session.post(
                f"{self._get_data_collector_url()}?api-version=2016-04-01",
                json=[log_entry],
                headers=headers,
                ssl=self._ssl_context
            ) as response:
                
                response_data = {}
                if response.content_type == 'application/json':
                    try:
                        response_data = await response.json()
                    except:
                        response_data = {"text": await response.text()}
                
                self._metrics['events_sent'] += 1
                
                return SiemResponse(
                    success=response.status == 200,
                    status_code=response.status,
                    message="Event sent to Sentinel",
                    data=response_data
                )
                
        except Exception as e:
            logger.error(f"Failed to send event to Sentinel: {e}")
            return SiemResponse(
                success=False,
                status_code=500,
                message=f"Failed to send event: {e}",
                error_details=str(e)
            )
    
    async def query_events(
        self,
        query: str,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 1000
    ) -> List[SiemEvent]:
        """Query events using KQL (Kusto Query Language)"""
        try:
            await self._refresh_access_token()
            
            # Build KQL query
            kql_query = query
            
            # Add time constraints if provided
            if start_time and end_time:
                time_filter = f"| where TimeGenerated >= datetime({start_time.isoformat()}) and TimeGenerated <= datetime({end_time.isoformat()})"
                if "where" not in kql_query.lower():
                    kql_query += f" {time_filter}"
                else:
                    kql_query = kql_query.replace(
                        kql_query[kql_query.lower().find("| where"):].split('|')[1],
                        f" where TimeGenerated >= datetime({start_time.isoformat()}) and TimeGenerated <= datetime({end_time.isoformat()}) and{kql_query[kql_query.lower().find('| where')+7:]}"
                    )
            
            # Add limit
            if "| take" not in kql_query.lower() and "| limit" not in kql_query.lower():
                kql_query += f" | take {limit}"
            
            # Execute query
            query_data = {
                "query": kql_query,
                "timespan": "PT24H"  # Default to last 24 hours if no time specified
            }
            
            response = await self._make_api_call(
                "POST",
                f"{self._get_logs_base_url()}/query",
                data=query_data,
                headers=self._get_auth_headers()
            )
            
            if not response.is_success():
                logger.error(f"Sentinel KQL query failed: {response.message}")
                return []
            
            # Parse results
            events = []
            if response.data and 'tables' in response.data:
                for table in response.data['tables']:
                    columns = [col['name'] for col in table.get('columns', [])]
                    rows = table.get('rows', [])
                    
                    for row in rows:
                        try:
                            row_data = dict(zip(columns, row))
                            
                            event = SiemEvent(
                                id=row_data.get('EventId', ''),
                                timestamp=datetime.fromisoformat(
                                    row_data.get('TimeGenerated', datetime.utcnow().isoformat()).replace('Z', '+00:00')
                                ),
                                source=row_data.get('Source', 'sentinel'),
                                event_type=row_data.get('EventType', 'unknown'),
                                severity=EventSeverity[row_data.get('Severity', 'MEDIUM')],
                                category=row_data.get('Category', 'security'),
                                message=row_data.get('Message', ''),
                                source_ip=row_data.get('SourceIP'),
                                destination_ip=row_data.get('DestinationIP'),
                                user_id=row_data.get('UserId'),
                                asset_id=row_data.get('AssetId'),
                                tags=row_data.get('Tags', '').split(',') if row_data.get('Tags') else [],
                                metadata=json.loads(row_data.get('Metadata', '{}')) if row_data.get('Metadata') else {},
                                raw_data=row_data
                            )
                            events.append(event)
                            
                        except Exception as e:
                            logger.warning(f"Failed to parse Sentinel event: {e}")
                            continue
            
            return events
            
        except Exception as e:
            logger.error(f"Failed to query Sentinel events: {e}")
            return []
    
    async def create_alert(
        self,
        title: str,
        description: str,
        severity: EventSeverity = EventSeverity.MEDIUM,
        metadata: Optional[Dict[str, Any]] = None
    ) -> SiemResponse:
        """Create incident in Microsoft Sentinel"""
        try:
            await self._refresh_access_token()
            
            # Map severity
            severity_mapping = {
                EventSeverity.CRITICAL: "High",
                EventSeverity.HIGH: "High",
                EventSeverity.MEDIUM: "Medium",
                EventSeverity.LOW: "Low",
                EventSeverity.INFO: "Informational"
            }
            
            incident_data = {
                "properties": {
                    "title": title,
                    "description": description,
                    "severity": severity_mapping.get(severity, "Medium"),
                    "status": "New",
                    "classification": "Undetermined",
                    "owner": {
                        "assignedTo": "isectech-ai-ml-system"
                    },
                    "labels": [
                        {
                            "labelName": "AI-ML-Detection",
                            "labelType": "System"
                        }
                    ],
                    "additionalData": {
                        "alertsCount": 1,
                        "bookmarksCount": 0,
                        "commentsCount": 0,
                        "alertProductNames": ["isectech AI/ML Threat Detection"],
                        "tactics": ["Discovery", "Collection"]
                    }
                }
            }
            
            # Add metadata as custom properties
            if metadata:
                incident_data["properties"]["additionalData"]["customDetails"] = metadata
            
            response = await self._make_api_call(
                "PUT",
                f"{self._workspace_resource_url}/providers/Microsoft.SecurityInsights/incidents/{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}-ai-ml-alert",
                data=incident_data,
                params={"api-version": "2023-02-01"}
            )
            
            return response
            
        except Exception as e:
            logger.error(f"Failed to create Sentinel incident: {e}")
            return SiemResponse(
                success=False,
                status_code=500,
                message=f"Failed to create incident: {e}",
                error_details=str(e)
            )
    
    async def _stream_events(self) -> AsyncGenerator[SiemEvent, None]:
        """Stream real-time events from Sentinel"""
        try:
            # Use polling approach with KQL queries
            last_poll_time = datetime.utcnow() - timedelta(minutes=5)
            
            while self._connection_status == ConnectionStatus.CONNECTED:
                try:
                    await self._refresh_access_token()
                    
                    current_time = datetime.utcnow()
                    
                    # Query recent events
                    kql_query = f"""
                    isectech_threat_events_CL
                    | where TimeGenerated >= datetime({last_poll_time.isoformat()})
                    | where TimeGenerated <= datetime({current_time.isoformat()})
                    | order by TimeGenerated desc
                    | take 100
                    """
                    
                    events = await self.query_events(kql_query, last_poll_time, current_time, 100)
                    
                    for event in events:
                        self._metrics['events_received'] += 1
                        self._metrics['last_activity'] = datetime.utcnow()
                        yield event
                    
                    last_poll_time = current_time
                    await asyncio.sleep(60)  # Poll every minute
                    
                except Exception as e:
                    logger.error(f"Error in Sentinel event streaming: {e}")
                    await asyncio.sleep(120)  # Wait longer on error
                    
        except Exception as e:
            logger.error(f"Failed to start Sentinel event stream: {e}")
    
    async def get_incidents(
        self,
        limit: int = 50,
        status: Optional[str] = "New"
    ) -> List[Dict[str, Any]]:
        """Get Sentinel incidents"""
        try:
            await self._refresh_access_token()
            
            params = {"api-version": "2023-02-01", "$top": limit}
            if status:
                params["$filter"] = f"properties/status eq '{status}'"
            
            response = await self._make_api_call(
                "GET",
                f"{self._workspace_resource_url}/providers/Microsoft.SecurityInsights/incidents",
                params=params
            )
            
            if response.is_success() and response.data:
                return response.data.get('value', [])
            
            return []
            
        except Exception as e:
            logger.error(f"Failed to get Sentinel incidents: {e}")
            return []
    
    async def update_incident(
        self,
        incident_id: str,
        status: str = "Closed",
        classification: str = "TruePositive",
        comment: Optional[str] = None
    ) -> bool:
        """Update Sentinel incident"""
        try:
            await self._refresh_access_token()
            
            update_data = {
                "properties": {
                    "status": status,
                    "classification": classification
                }
            }
            
            if comment:
                # Add comment (requires separate API call)
                comment_data = {
                    "properties": {
                        "message": comment,
                        "author": {
                            "name": "isectech-ai-ml-system",
                            "email": "ai-ml-system@isectech.com"
                        }
                    }
                }
                
                await self._make_api_call(
                    "PUT",
                    f"{self._workspace_resource_url}/providers/Microsoft.SecurityInsights/incidents/{incident_id}/comments/{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}",
                    data=comment_data,
                    params={"api-version": "2023-02-01"}
                )
            
            response = await self._make_api_call(
                "PATCH",
                f"{self._workspace_resource_url}/providers/Microsoft.SecurityInsights/incidents/{incident_id}",
                data=update_data,
                params={"api-version": "2023-02-01"}
            )
            
            return response.is_success()
            
        except Exception as e:
            logger.error(f"Failed to update Sentinel incident {incident_id}: {e}")
            return False
    
    async def create_watchlist_item(
        self,
        watchlist_alias: str,
        item_data: Dict[str, Any]
    ) -> bool:
        """Add item to Sentinel watchlist"""
        try:
            await self._refresh_access_token()
            
            watchlist_item = {
                "properties": {
                    "itemsKeyValue": item_data,
                    "created": datetime.utcnow().isoformat(),
                    "createdBy": {
                        "name": "isectech-ai-ml-system"
                    }
                }
            }
            
            item_id = f"ai-ml-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}"
            
            response = await self._make_api_call(
                "PUT",
                f"{self._workspace_resource_url}/providers/Microsoft.SecurityInsights/watchlists/{watchlist_alias}/watchlistItems/{item_id}",
                data=watchlist_item,
                params={"api-version": "2023-02-01"}
            )
            
            return response.is_success()
            
        except Exception as e:
            logger.error(f"Failed to create watchlist item: {e}")
            return False