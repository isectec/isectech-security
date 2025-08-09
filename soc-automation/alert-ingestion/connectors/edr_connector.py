"""
EDR Connector - Endpoint Detection and Response platform connector

Supports multiple EDR platforms including CrowdStrike, SentinelOne, Carbon Black,
and Microsoft Defender for Endpoint with real-time alert streaming.
"""

import asyncio
import json
import hmac
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, AsyncGenerator, Optional
from urllib.parse import urlencode, quote
import aiohttp
import structlog

from .base_connector import BaseConnector

logger = structlog.get_logger(__name__)

class EDRConnector(BaseConnector):
    """
    Universal EDR connector that integrates with major Endpoint Detection
    and Response platforms through their APIs.
    
    Supported EDR platforms:
    - CrowdStrike Falcon (REST API & Streaming API)
    - SentinelOne (REST API)
    - VMware Carbon Black (REST API)
    - Microsoft Defender for Endpoint (Graph API)
    - Cybereason (REST API)
    - Generic EDR (configurable endpoints)
    """
    
    def __init__(self, name: str, config: Dict[str, Any]):
        super().__init__(name, config)
        
        # Validate required configuration
        required_fields = ['edr_type', 'base_url']
        self._validate_config(required_fields)
        
        # EDR-specific configuration
        self.edr_type = config['edr_type'].lower()
        self.base_url = config['base_url'].rstrip('/')
        self.client_id = config.get('client_id')
        self.client_secret = config.get('client_secret')
        self.api_key = config.get('api_key')
        self.tenant_id = config.get('tenant_id')  # For Microsoft
        self.org_key = config.get('org_key')      # For Carbon Black
        self.verify_ssl = config.get('verify_ssl', True)
        
        # API configuration
        self.api_version = config.get('api_version', 'v1')
        self.polling_interval = config.get('polling_interval', 30)  # seconds
        self.max_events = config.get('max_events', 500)
        self.detection_types = config.get('detection_types', ['all'])
        self.severity_filter = config.get('severity_filter', ['high', 'critical'])
        
        # Connection state
        self.session: Optional[aiohttp.ClientSession] = None
        self.access_token: Optional[str] = None
        self.token_expires_at: Optional[datetime] = None
        self.last_poll_time: Optional[datetime] = None
        
        # Streaming configuration
        self.use_streaming = config.get('use_streaming', False)
        self.stream_url: Optional[str] = None
        
        logger.info("EDRConnector initialized",
                   edr_type=self.edr_type,
                   base_url=self.base_url,
                   polling_interval=self.polling_interval,
                   use_streaming=self.use_streaming)
    
    async def _initialize_connection(self):
        """Initialize connection to EDR platform"""
        try:
            # Create HTTP session
            connector = aiohttp.TCPConnector(
                verify_ssl=self.verify_ssl,
                limit=100,
                limit_per_host=20,
                keepalive_timeout=30
            )
            
            timeout = aiohttp.ClientTimeout(total=60)
            self.session = aiohttp.ClientSession(
                connector=connector,
                timeout=timeout,
                headers={
                    'User-Agent': 'iSECTECH-SOC-Automation/1.0',
                    'Content-Type': 'application/json'
                }
            )
            
            # Authenticate with EDR platform
            await self._authenticate()
            
            # Test connection
            await self._test_connection()
            
            # Initialize polling state
            self.last_poll_time = datetime.now(timezone.utc) - timedelta(minutes=5)
            
            logger.info("EDR connection initialized successfully")
            
        except Exception as e:
            logger.error("Failed to initialize EDR connection", error=str(e))
            if self.session:
                await self.session.close()
            raise
    
    async def _close_connection(self):
        """Close connection to EDR platform"""
        if self.session:
            await self.session.close()
            self.session = None
        
        self.access_token = None
        self.token_expires_at = None
        logger.info("EDR connection closed")
    
    async def _authenticate(self):
        """Authenticate with EDR platform"""
        if self.edr_type == 'crowdstrike':
            await self._authenticate_crowdstrike()
        elif self.edr_type == 'sentinelone':
            await self._authenticate_sentinelone()
        elif self.edr_type == 'carbonblack':
            await self._authenticate_carbonblack()
        elif self.edr_type == 'microsoft':
            await self._authenticate_microsoft()
        elif self.edr_type == 'cybereason':
            await self._authenticate_cybereason()
        else:
            await self._authenticate_generic()
    
    async def _authenticate_crowdstrike(self):
        """Authenticate with CrowdStrike Falcon API"""
        if not self.client_id or not self.client_secret:
            raise Exception("CrowdStrike authentication requires client_id and client_secret")
        
        auth_url = f"{self.base_url}/oauth2/token"
        data = {
            'client_id': self.client_id,
            'client_secret': self.client_secret
        }
        
        async with self.session.post(auth_url, data=data) as response:
            if response.status == 201:
                token_data = await response.json()
                self.access_token = token_data.get('access_token')
                expires_in = token_data.get('expires_in', 3600)
                self.token_expires_at = datetime.now(timezone.utc) + timedelta(seconds=expires_in)
                
                logger.info("CrowdStrike authentication successful",
                           expires_in=expires_in)
            else:
                error_text = await response.text()
                raise Exception(f"CrowdStrike authentication failed: {response.status} - {error_text}")
    
    async def _authenticate_sentinelone(self):
        """Authenticate with SentinelOne API"""
        if self.api_key:
            # API key authentication
            self.access_token = self.api_key
            self.token_expires_at = datetime.now(timezone.utc) + timedelta(days=365)
        else:
            raise Exception("SentinelOne authentication requires api_key")
    
    async def _authenticate_carbonblack(self):
        """Authenticate with Carbon Black API"""
        if not self.api_key or not self.org_key:
            raise Exception("Carbon Black authentication requires api_key and org_key")
        
        # Carbon Black uses API key authentication
        self.access_token = self.api_key
        self.token_expires_at = datetime.now(timezone.utc) + timedelta(days=365)
    
    async def _authenticate_microsoft(self):
        """Authenticate with Microsoft Defender for Endpoint"""
        if not self.client_id or not self.client_secret or not self.tenant_id:
            raise Exception("Microsoft authentication requires client_id, client_secret, and tenant_id")
        
        auth_url = f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"
        data = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'scope': 'https://api.securitycenter.microsoft.com/.default',
            'grant_type': 'client_credentials'
        }
        
        async with self.session.post(auth_url, data=data) as response:
            if response.status == 200:
                token_data = await response.json()
                self.access_token = token_data.get('access_token')
                expires_in = token_data.get('expires_in', 3600)
                self.token_expires_at = datetime.now(timezone.utc) + timedelta(seconds=expires_in)
                
                logger.info("Microsoft authentication successful",
                           expires_in=expires_in)
            else:
                error_text = await response.text()
                raise Exception(f"Microsoft authentication failed: {response.status} - {error_text}")
    
    async def _authenticate_cybereason(self):
        """Authenticate with Cybereason API"""
        if self.api_key:
            self.access_token = self.api_key
            self.token_expires_at = datetime.now(timezone.utc) + timedelta(days=365)
        else:
            raise Exception("Cybereason authentication requires api_key")
    
    async def _authenticate_generic(self):
        """Generic EDR authentication"""
        if self.api_key:
            self.access_token = self.api_key
            self.token_expires_at = datetime.now(timezone.utc) + timedelta(days=365)
        else:
            raise Exception("Generic EDR authentication requires api_key")
    
    async def _test_connection(self):
        """Test connection to EDR platform"""
        test_endpoints = {
            'crowdstrike': '/sensors/queries/sensors/v1?limit=1',
            'sentinelone': '/web/api/v2.1/system/status',
            'carbonblack': '/api/investigate/v1/orgs',
            'microsoft': '/api/alerts',
            'cybereason': '/rest/version',
            'generic': '/health'
        }
        
        test_path = test_endpoints.get(self.edr_type, '/health')
        test_url = f"{self.base_url}{test_path}"
        
        headers = await self._get_auth_headers()
        
        async with self.session.get(test_url, headers=headers) as response:
            if response.status not in [200, 201]:
                error_text = await response.text()
                raise Exception(f"EDR connection test failed: {response.status} - {error_text}")
        
        logger.info("EDR connection test successful")
    
    async def _get_auth_headers(self) -> Dict[str, str]:
        """Get authentication headers for API requests"""
        headers = {}
        
        # Check if token needs refresh
        if (self.token_expires_at and 
            datetime.now(timezone.utc) + timedelta(minutes=5) >= self.token_expires_at):
            await self._authenticate()
        
        if self.edr_type == 'crowdstrike':
            headers['Authorization'] = f'Bearer {self.access_token}'
        elif self.edr_type == 'sentinelone':
            headers['Authorization'] = f'ApiToken {self.access_token}'
        elif self.edr_type == 'carbonblack':
            headers['X-Auth-Token'] = f'{self.access_token}/{self.org_key}'
        elif self.edr_type == 'microsoft':
            headers['Authorization'] = f'Bearer {self.access_token}'
        elif self.edr_type == 'cybereason':
            headers['Authorization'] = f'Bearer {self.access_token}'
        else:
            headers['X-API-Key'] = self.access_token
        
        return headers
    
    async def _fetch_alerts(self) -> AsyncGenerator[List[Dict[str, Any]], None]:
        """Fetch alerts from EDR platform"""
        if self.use_streaming and self.edr_type == 'crowdstrike':
            async for alerts in self._stream_crowdstrike_alerts():
                yield alerts
        else:
            async for alerts in self._poll_alerts():
                yield alerts
    
    async def _poll_alerts(self) -> AsyncGenerator[List[Dict[str, Any]], None]:
        """Poll for alerts using REST API"""
        while self._running:
            try:
                current_time = datetime.now(timezone.utc)
                
                # Fetch alerts based on EDR type
                if self.edr_type == 'crowdstrike':
                    alerts = await self._fetch_crowdstrike_detections()
                elif self.edr_type == 'sentinelone':
                    alerts = await self._fetch_sentinelone_threats()
                elif self.edr_type == 'carbonblack':
                    alerts = await self._fetch_carbonblack_alerts()
                elif self.edr_type == 'microsoft':
                    alerts = await self._fetch_microsoft_alerts()
                elif self.edr_type == 'cybereason':
                    alerts = await self._fetch_cybereason_detections()
                else:
                    alerts = await self._fetch_generic_edr_alerts()
                
                if alerts:
                    logger.info("Fetched EDR alerts",
                              count=len(alerts),
                              edr_type=self.edr_type)
                    yield alerts
                
                self.last_poll_time = current_time
                await asyncio.sleep(self.polling_interval)
                
            except Exception as e:
                logger.error("Error polling EDR alerts",
                            edr_type=self.edr_type,
                            error=str(e))
                await asyncio.sleep(self.retry_delay)
    
    async def _fetch_crowdstrike_detections(self) -> List[Dict[str, Any]]:
        """Fetch detections from CrowdStrike Falcon"""
        headers = await self._get_auth_headers()
        
        # Get detection IDs first
        query_params = {
            'filter': f'created_timestamp:>="{self.last_poll_time.isoformat()}"',
            'limit': self.max_events,
            'sort': 'created_timestamp.desc'
        }
        
        ids_url = f"{self.base_url}/detects/queries/detects/v1"
        
        async with self.session.get(ids_url, params=query_params, headers=headers) as response:
            if response.status != 200:
                raise Exception(f"Failed to get CrowdStrike detection IDs: {response.status}")
            
            ids_data = await response.json()
            detection_ids = ids_data.get('resources', [])
            
            if not detection_ids:
                return []
        
        # Get detailed detection data
        details_url = f"{self.base_url}/detects/entities/summaries/GET/v1"
        details_payload = {'ids': detection_ids}
        
        async with self.session.post(details_url, json=details_payload, headers=headers) as response:
            if response.status == 200:
                details_data = await response.json()
                return details_data.get('resources', [])
            else:
                raise Exception(f"Failed to get CrowdStrike detection details: {response.status}")
    
    async def _fetch_sentinelone_threats(self) -> List[Dict[str, Any]]:
        """Fetch threats from SentinelOne"""
        headers = await self._get_auth_headers()
        
        params = {
            'createdAt__gte': self.last_poll_time.isoformat(),
            'limit': self.max_events,
            'sortBy': 'createdAt',
            'sortOrder': 'desc'
        }
        
        # Add severity filter if specified
        if self.severity_filter and 'all' not in self.severity_filter:
            params['confidenceLevel__in'] = ','.join(self.severity_filter)
        
        threats_url = f"{self.base_url}/web/api/v2.1/threats"
        
        async with self.session.get(threats_url, params=params, headers=headers) as response:
            if response.status == 200:
                data = await response.json()
                return data.get('data', [])
            else:
                raise Exception(f"Failed to fetch SentinelOne threats: {response.status}")
    
    async def _fetch_carbonblack_alerts(self) -> List[Dict[str, Any]]:
        """Fetch alerts from Carbon Black"""
        headers = await self._get_auth_headers()
        
        # Build search criteria
        criteria = {
            'time_range': {
                'start': self.last_poll_time.isoformat(),
                'end': datetime.now(timezone.utc).isoformat()
            },
            'rows': self.max_events
        }
        
        # Add severity filter
        if self.severity_filter and 'all' not in self.severity_filter:
            criteria['minimum_severity'] = min([
                {'low': 1, 'medium': 4, 'high': 7, 'critical': 9}.get(s, 1) 
                for s in self.severity_filter
            ])
        
        alerts_url = f"{self.base_url}/api/investigate/v2/orgs/{self.org_key}/alerts/_search"
        
        async with self.session.post(alerts_url, json=criteria, headers=headers) as response:
            if response.status == 200:
                data = await response.json()
                return data.get('results', [])
            else:
                raise Exception(f"Failed to fetch Carbon Black alerts: {response.status}")
    
    async def _fetch_microsoft_alerts(self) -> List[Dict[str, Any]]:
        """Fetch alerts from Microsoft Defender for Endpoint"""
        headers = await self._get_auth_headers()
        
        # Build OData filter
        filter_time = self.last_poll_time.strftime('%Y-%m-%dT%H:%M:%S.%fZ')
        odata_filter = f"alertCreationTime ge {filter_time}"
        
        if self.severity_filter and 'all' not in self.severity_filter:
            severity_conditions = " or ".join([
                f"severity eq '{s.title()}'" for s in self.severity_filter
            ])
            odata_filter += f" and ({severity_conditions})"
        
        params = {
            '$filter': odata_filter,
            '$top': self.max_events,
            '$orderby': 'alertCreationTime desc'
        }
        
        alerts_url = f"{self.base_url}/api/alerts"
        
        async with self.session.get(alerts_url, params=params, headers=headers) as response:
            if response.status == 200:
                data = await response.json()
                return data.get('value', [])
            else:
                raise Exception(f"Failed to fetch Microsoft alerts: {response.status}")
    
    async def _fetch_cybereason_detections(self) -> List[Dict[str, Any]]:
        """Fetch detections from Cybereason"""
        headers = await self._get_auth_headers()
        
        # Cybereason API call
        query = {
            'templateContext': 'OVERVIEW',
            'queryPath': [
                {
                    'requestedType': 'MalwareProcess',
                    'filters': [
                        {
                            'facetName': 'creationTime',
                            'filterType': 'GreaterThan',
                            'values': [int(self.last_poll_time.timestamp() * 1000)]
                        }
                    ]
                }
            ]
        }
        
        detections_url = f"{self.base_url}/rest/visualsearch/query/simple"
        
        async with self.session.post(detections_url, json=query, headers=headers) as response:
            if response.status == 200:
                data = await response.json()
                return data.get('data', {}).get('resultIdToElementDataMap', {}).values()
            else:
                raise Exception(f"Failed to fetch Cybereason detections: {response.status}")
    
    async def _fetch_generic_edr_alerts(self) -> List[Dict[str, Any]]:
        """Fetch alerts from generic EDR API"""
        headers = await self._get_auth_headers()
        
        params = {
            'start_time': self.last_poll_time.isoformat(),
            'end_time': datetime.now(timezone.utc).isoformat(),
            'limit': self.max_events
        }
        
        if self.severity_filter and 'all' not in self.severity_filter:
            params['severity'] = ','.join(self.severity_filter)
        
        alerts_url = f"{self.base_url}/api/{self.api_version}/alerts"
        
        async with self.session.get(alerts_url, params=params, headers=headers) as response:
            if response.status == 200:
                data = await response.json()
                if isinstance(data, list):
                    return data
                elif isinstance(data, dict):
                    return data.get('alerts', data.get('data', data.get('results', [])))
                else:
                    return []
            else:
                raise Exception(f"Failed to fetch generic EDR alerts: {response.status}")
    
    async def _stream_crowdstrike_alerts(self) -> AsyncGenerator[List[Dict[str, Any]], None]:
        """Stream alerts from CrowdStrike Event Stream API"""
        # This is a simplified implementation of CrowdStrike streaming
        # In production, you would use their Event Stream API with proper offset management
        
        headers = await self._get_auth_headers()
        
        # Discover available event streams
        streams_url = f"{self.base_url}/sensors/entities/datafeed/v2"
        
        while self._running:
            try:
                async with self.session.get(streams_url, headers=headers) as response:
                    if response.status == 200:
                        streams_data = await response.json()
                        # Process stream data (simplified)
                        # In reality, you would maintain persistent connections and handle offsets
                        yield []  # Placeholder for actual streaming implementation
                    
                await asyncio.sleep(1)  # Adjust based on stream characteristics
                
            except Exception as e:
                logger.error("CrowdStrike streaming error", error=str(e))
                await asyncio.sleep(self.retry_delay)
    
    async def _health_check(self) -> bool:
        """Perform health check on EDR connection"""
        try:
            if not self.session or not self.access_token:
                return False
            
            await self._test_connection()
            return True
            
        except Exception as e:
            logger.warning("EDR health check failed", error=str(e))
            return False
    
    def get_platform_status(self) -> Dict[str, Any]:
        """Get EDR platform specific status information"""
        return {
            'edr_type': self.edr_type,
            'base_url': self.base_url,
            'last_poll_time': self.last_poll_time.isoformat() if self.last_poll_time else None,
            'polling_interval': self.polling_interval,
            'max_events': self.max_events,
            'detection_types': self.detection_types,
            'severity_filter': self.severity_filter,
            'use_streaming': self.use_streaming,
            'token_expires_at': self.token_expires_at.isoformat() if self.token_expires_at else None,
            'authenticated': self.access_token is not None
        }