"""
SIEM Connector - Universal connector for SIEM platforms

Supports multiple SIEM platforms including Splunk, QRadar, ArcSight, and Elastic Security
with configurable API endpoints and authentication methods.
"""

import asyncio
import json
import base64
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, AsyncGenerator, Optional
from urllib.parse import urlencode
import aiohttp
import structlog

from .base_connector import BaseConnector

logger = structlog.get_logger(__name__)

class SIEMConnector(BaseConnector):
    """
    Universal SIEM connector that can integrate with multiple SIEM platforms
    through their REST APIs or data export mechanisms.
    
    Supported SIEM platforms:
    - Splunk (REST API)
    - IBM QRadar (REST API)  
    - Micro Focus ArcSight (REST API)
    - Elastic Security (Elasticsearch API)
    - Generic SIEM (configurable endpoints)
    """
    
    def __init__(self, name: str, config: Dict[str, Any]):
        super().__init__(name, config)
        
        # Validate required configuration
        required_fields = ['siem_type', 'base_url']
        self._validate_config(required_fields)
        
        # SIEM-specific configuration
        self.siem_type = config['siem_type'].lower()
        self.base_url = config['base_url'].rstrip('/')
        self.username = config.get('username')
        self.password = config.get('password')
        self.api_key = config.get('api_key')
        self.token = config.get('token')
        self.cert_path = config.get('cert_path')
        self.verify_ssl = config.get('verify_ssl', True)
        
        # Query configuration
        self.query_interval = config.get('query_interval', 60)  # seconds
        self.max_results = config.get('max_results', 1000)
        self.time_field = config.get('time_field', 'timestamp')
        self.custom_query = config.get('custom_query')
        self.search_window = config.get('search_window', 300)  # 5 minutes
        
        # HTTP session
        self.session: Optional[aiohttp.ClientSession] = None
        self.auth_headers: Dict[str, str] = {}
        
        # State tracking
        self.last_query_time = None
        
        logger.info("SIEMConnector initialized",
                   siem_type=self.siem_type,
                   base_url=self.base_url,
                   query_interval=self.query_interval)
    
    async def _initialize_connection(self):
        """Initialize connection to SIEM platform"""
        try:
            # Create HTTP session
            connector = aiohttp.TCPConnector(
                verify_ssl=self.verify_ssl,
                limit=100,
                limit_per_host=20
            )
            
            timeout = aiohttp.ClientTimeout(total=30)
            self.session = aiohttp.ClientSession(
                connector=connector,
                timeout=timeout,
                headers={'User-Agent': 'iSECTECH-SOC-Automation/1.0'}
            )
            
            # Initialize authentication
            await self._initialize_auth()
            
            # Test connection
            await self._test_connection()
            
            # Initialize query state
            self.last_query_time = datetime.now(timezone.utc) - timedelta(seconds=self.search_window)
            
            logger.info("SIEM connection initialized successfully")
            
        except Exception as e:
            logger.error("Failed to initialize SIEM connection", error=str(e))
            if self.session:
                await self.session.close()
            raise
    
    async def _close_connection(self):
        """Close connection to SIEM platform"""
        if self.session:
            await self.session.close()
            self.session = None
        
        logger.info("SIEM connection closed")
    
    async def _initialize_auth(self):
        """Initialize authentication for SIEM platform"""
        if self.siem_type == 'splunk':
            await self._initialize_splunk_auth()
        elif self.siem_type == 'qradar':
            await self._initialize_qradar_auth()
        elif self.siem_type == 'arcsight':
            await self._initialize_arcsight_auth()
        elif self.siem_type == 'elastic':
            await self._initialize_elastic_auth()
        else:
            await self._initialize_generic_auth()
    
    async def _initialize_splunk_auth(self):
        """Initialize Splunk authentication"""
        if self.token:
            self.auth_headers['Authorization'] = f'Splunk {self.token}'
        elif self.username and self.password:
            # Get session token
            auth_url = f"{self.base_url}/services/auth/login"
            data = {
                'username': self.username,
                'password': self.password,
                'output_mode': 'json'
            }
            
            async with self.session.post(auth_url, data=data) as response:
                if response.status == 200:
                    auth_data = await response.json()
                    session_key = auth_data.get('sessionKey')
                    if session_key:
                        self.auth_headers['Authorization'] = f'Splunk {session_key}'
                        logger.info("Splunk authentication successful")
                    else:
                        raise Exception("Failed to get Splunk session key")
                else:
                    raise Exception(f"Splunk authentication failed: {response.status}")
        else:
            raise Exception("Splunk authentication requires token or username/password")
    
    async def _initialize_qradar_auth(self):
        """Initialize QRadar authentication"""
        if self.token:
            self.auth_headers['SEC'] = self.token
        elif self.username and self.password:
            # QRadar uses basic auth for some endpoints
            credentials = base64.b64encode(f"{self.username}:{self.password}".encode()).decode()
            self.auth_headers['Authorization'] = f'Basic {credentials}'
        else:
            raise Exception("QRadar authentication requires token or username/password")
    
    async def _initialize_arcsight_auth(self):
        """Initialize ArcSight authentication"""
        if self.username and self.password:
            # ArcSight typically uses basic auth
            credentials = base64.b64encode(f"{self.username}:{self.password}".encode()).decode()
            self.auth_headers['Authorization'] = f'Basic {credentials}'
        else:
            raise Exception("ArcSight authentication requires username/password")
    
    async def _initialize_elastic_auth(self):
        """Initialize Elastic Security authentication"""
        if self.api_key:
            self.auth_headers['Authorization'] = f'ApiKey {self.api_key}'
        elif self.username and self.password:
            credentials = base64.b64encode(f"{self.username}:{self.password}".encode()).decode()
            self.auth_headers['Authorization'] = f'Basic {credentials}'
        else:
            raise Exception("Elastic authentication requires api_key or username/password")
    
    async def _initialize_generic_auth(self):
        """Initialize generic authentication"""
        if self.api_key:
            self.auth_headers['X-API-Key'] = self.api_key
        elif self.token:
            self.auth_headers['Authorization'] = f'Bearer {self.token}'
        elif self.username and self.password:
            credentials = base64.b64encode(f"{self.username}:{self.password}".encode()).decode()
            self.auth_headers['Authorization'] = f'Basic {credentials}'
    
    async def _test_connection(self):
        """Test connection to SIEM platform"""
        if self.siem_type == 'splunk':
            test_url = f"{self.base_url}/services/server/info"
        elif self.siem_type == 'qradar':
            test_url = f"{self.base_url}/api/system/about"
        elif self.siem_type == 'elastic':
            test_url = f"{self.base_url}/_cluster/health"
        else:
            test_url = f"{self.base_url}/health"  # Generic health endpoint
        
        async with self.session.get(test_url, headers=self.auth_headers) as response:
            if response.status not in [200, 201]:
                raise Exception(f"SIEM connection test failed: {response.status}")
        
        logger.info("SIEM connection test successful")
    
    async def _fetch_alerts(self) -> AsyncGenerator[List[Dict[str, Any]], None]:
        """Fetch alerts from SIEM platform"""
        while self._running:
            try:
                current_time = datetime.now(timezone.utc)
                
                # Calculate search time window
                start_time = self.last_query_time
                end_time = current_time
                
                # Fetch alerts based on SIEM type
                if self.siem_type == 'splunk':
                    alerts = await self._fetch_splunk_alerts(start_time, end_time)
                elif self.siem_type == 'qradar':
                    alerts = await self._fetch_qradar_alerts(start_time, end_time)
                elif self.siem_type == 'arcsight':
                    alerts = await self._fetch_arcsight_alerts(start_time, end_time)
                elif self.siem_type == 'elastic':
                    alerts = await self._fetch_elastic_alerts(start_time, end_time)
                else:
                    alerts = await self._fetch_generic_alerts(start_time, end_time)
                
                if alerts:
                    logger.info("Fetched alerts from SIEM",
                              count=len(alerts),
                              siem_type=self.siem_type)
                    yield alerts
                
                # Update last query time
                self.last_query_time = end_time
                
                # Wait before next query
                await asyncio.sleep(self.query_interval)
                
            except Exception as e:
                logger.error("Error fetching SIEM alerts",
                            siem_type=self.siem_type,
                            error=str(e))
                await asyncio.sleep(self.retry_delay)
    
    async def _fetch_splunk_alerts(
        self, 
        start_time: datetime, 
        end_time: datetime
    ) -> List[Dict[str, Any]]:
        """Fetch alerts from Splunk"""
        # Build Splunk search query
        if self.custom_query:
            search_query = self.custom_query
        else:
            search_query = (
                f'search index=* earliest={int(start_time.timestamp())} '
                f'latest={int(end_time.timestamp())} '
                f'| head {self.max_results}'
            )
        
        # Create search job
        search_url = f"{self.base_url}/services/search/jobs"
        search_data = {
            'search': search_query,
            'output_mode': 'json'
        }
        
        async with self.session.post(
            search_url, 
            data=search_data, 
            headers=self.auth_headers
        ) as response:
            if response.status != 201:
                raise Exception(f"Failed to create Splunk search: {response.status}")
            
            search_result = await response.json()
            search_id = search_result.get('sid')
            
            if not search_id:
                raise Exception("No search ID returned from Splunk")
        
        # Wait for search to complete and get results
        results_url = f"{self.base_url}/services/search/jobs/{search_id}/results"
        
        # Poll for completion
        for _ in range(30):  # 30 second timeout
            status_url = f"{self.base_url}/services/search/jobs/{search_id}"
            async with self.session.get(status_url, headers=self.auth_headers) as response:
                if response.status == 200:
                    status_data = await response.json()
                    if status_data.get('entry', [{}])[0].get('content', {}).get('isDone'):
                        break
            await asyncio.sleep(1)
        
        # Get results
        params = {'output_mode': 'json'}
        async with self.session.get(
            results_url, 
            params=params, 
            headers=self.auth_headers
        ) as response:
            if response.status == 200:
                results_data = await response.json()
                return results_data.get('results', [])
            else:
                raise Exception(f"Failed to get Splunk results: {response.status}")
    
    async def _fetch_qradar_alerts(
        self, 
        start_time: datetime, 
        end_time: datetime
    ) -> List[Dict[str, Any]]:
        """Fetch alerts from QRadar"""
        # QRadar uses milliseconds for timestamps
        start_ms = int(start_time.timestamp() * 1000)
        end_ms = int(end_time.timestamp() * 1000)
        
        # Build QRadar API request
        url = f"{self.base_url}/api/siem/offenses"
        params = {
            'filter': f'start_time >= {start_ms} and start_time <= {end_ms}',
            'fields': 'id,description,start_time,event_count,severity,status,offense_type,source_address_ids,local_destination_address_ids',
            'Range': f'items=0-{self.max_results-1}'
        }
        
        async with self.session.get(
            url, 
            params=params, 
            headers=self.auth_headers
        ) as response:
            if response.status == 200:
                return await response.json()
            else:
                raise Exception(f"Failed to fetch QRadar alerts: {response.status}")
    
    async def _fetch_arcsight_alerts(
        self, 
        start_time: datetime, 
        end_time: datetime
    ) -> List[Dict[str, Any]]:
        """Fetch alerts from ArcSight"""
        # ArcSight API request (simplified example)
        url = f"{self.base_url}/www/core-service/rest/ActiveListService/getEntries"
        
        # Build time filter
        time_filter = {
            'startTime': int(start_time.timestamp() * 1000),
            'endTime': int(end_time.timestamp() * 1000)
        }
        
        async with self.session.post(
            url, 
            json=time_filter, 
            headers=self.auth_headers
        ) as response:
            if response.status == 200:
                data = await response.json()
                return data.get('entries', [])
            else:
                raise Exception(f"Failed to fetch ArcSight alerts: {response.status}")
    
    async def _fetch_elastic_alerts(
        self, 
        start_time: datetime, 
        end_time: datetime
    ) -> List[Dict[str, Any]]:
        """Fetch alerts from Elastic Security"""
        # Build Elasticsearch query
        query = {
            "query": {
                "bool": {
                    "must": [
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": start_time.isoformat(),
                                    "lte": end_time.isoformat()
                                }
                            }
                        }
                    ],
                    "filter": [
                        {
                            "exists": {
                                "field": "event.category"
                            }
                        }
                    ]
                }
            },
            "size": self.max_results,
            "sort": [
                {
                    "@timestamp": {
                        "order": "desc"
                    }
                }
            ]
        }
        
        if self.custom_query:
            query = self.custom_query
        
        # Search endpoint
        url = f"{self.base_url}/signals-*/_search"
        
        async with self.session.post(
            url, 
            json=query, 
            headers=self.auth_headers
        ) as response:
            if response.status == 200:
                data = await response.json()
                hits = data.get('hits', {}).get('hits', [])
                return [hit['_source'] for hit in hits]
            else:
                raise Exception(f"Failed to fetch Elastic alerts: {response.status}")
    
    async def _fetch_generic_alerts(
        self, 
        start_time: datetime, 
        end_time: datetime
    ) -> List[Dict[str, Any]]:
        """Fetch alerts from generic SIEM API"""
        # Generic API request with time parameters
        url = f"{self.base_url}/api/alerts"
        params = {
            'start_time': start_time.isoformat(),
            'end_time': end_time.isoformat(),
            'limit': self.max_results
        }
        
        if self.custom_query:
            params['query'] = self.custom_query
        
        async with self.session.get(
            url, 
            params=params, 
            headers=self.auth_headers
        ) as response:
            if response.status == 200:
                data = await response.json()
                # Handle different response formats
                if isinstance(data, list):
                    return data
                elif isinstance(data, dict):
                    return data.get('alerts', data.get('results', data.get('data', [])))
                else:
                    return []
            else:
                raise Exception(f"Failed to fetch generic SIEM alerts: {response.status}")
    
    async def _health_check(self) -> bool:
        """Perform health check on SIEM connection"""
        try:
            if not self.session:
                return False
            
            await self._test_connection()
            return True
            
        except Exception as e:
            logger.warning("SIEM health check failed", error=str(e))
            return False
    
    def update_last_query_time(self, timestamp: datetime):
        """Update the last query time (for external coordination)"""
        self.last_query_time = timestamp
        logger.debug("Updated last query time", timestamp=timestamp.isoformat())
    
    def get_query_status(self) -> Dict[str, Any]:
        """Get current query status information"""
        return {
            'siem_type': self.siem_type,
            'base_url': self.base_url,
            'last_query_time': self.last_query_time.isoformat() if self.last_query_time else None,
            'query_interval': self.query_interval,
            'max_results': self.max_results,
            'search_window': self.search_window,
            'authenticated': bool(self.auth_headers),
            'session_active': self.session is not None
        }