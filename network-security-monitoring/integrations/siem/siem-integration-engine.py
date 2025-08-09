#!/usr/bin/env python3
"""
iSECTECH SIEM Integration Engine
Production-grade SIEM integration for Network Security Monitoring

This engine provides comprehensive integration with multiple SIEM platforms
including Splunk, Elastic Stack, QRadar, ArcSight, and LogRhythm.
"""

import asyncio
import json
import logging
import sqlite3
import time
from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union
from pathlib import Path

import aiohttp
import redis
import yaml
from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk
import splunklib.client as splunk_client
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


@dataclass
class SIEMEvent:
    """Standardized SIEM event structure"""
    event_id: str
    timestamp: datetime
    source: str
    event_type: str
    severity: str
    title: str
    description: str
    raw_data: Dict[str, Any]
    metadata: Dict[str, Any]
    enrichment: Dict[str, Any]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format"""
        data = asdict(self)
        data['timestamp'] = self.timestamp.isoformat()
        return data
    
    def to_cef(self) -> str:
        """Convert to Common Event Format"""
        cef_header = f"CEF:0|iSECTECH|NSM|1.0|{self.event_type}|{self.title}|{self._severity_to_cef()}|"
        
        extensions = []
        extensions.append(f"rt={int(self.timestamp.timestamp() * 1000)}")
        extensions.append(f"src={self.metadata.get('src_ip', 'unknown')}")
        extensions.append(f"dst={self.metadata.get('dst_ip', 'unknown')}")
        extensions.append(f"spt={self.metadata.get('src_port', 0)}")
        extensions.append(f"dpt={self.metadata.get('dst_port', 0)}")
        extensions.append(f"proto={self.metadata.get('protocol', 'unknown')}")
        extensions.append(f"msg={self.description}")
        
        return cef_header + " ".join(extensions)
    
    def _severity_to_cef(self) -> int:
        """Convert severity to CEF numeric scale"""
        severity_map = {
            'critical': 10,
            'high': 8,
            'medium': 5,
            'low': 3,
            'info': 1
        }
        return severity_map.get(self.severity.lower(), 5)


class BaseSIEMConnector(ABC):
    """Abstract base class for SIEM connectors"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.name = config.get('name', 'unknown')
        self.enabled = config.get('enabled', False)
        self.logger = logging.getLogger(f"{self.__class__.__name__}")
        
    @abstractmethod
    async def send_event(self, event: SIEMEvent) -> bool:
        """Send a single event to SIEM"""
        pass
    
    @abstractmethod
    async def send_events_batch(self, events: List[SIEMEvent]) -> Dict[str, Any]:
        """Send multiple events in batch"""
        pass
    
    @abstractmethod
    async def test_connection(self) -> bool:
        """Test connectivity to SIEM platform"""
        pass
    
    async def health_check(self) -> Dict[str, Any]:
        """Perform health check"""
        try:
            connected = await self.test_connection()
            return {
                'connector': self.name,
                'status': 'healthy' if connected else 'unhealthy',
                'timestamp': datetime.utcnow().isoformat(),
                'connected': connected
            }
        except Exception as e:
            return {
                'connector': self.name,
                'status': 'error',
                'timestamp': datetime.utcnow().isoformat(),
                'error': str(e)
            }


class SplunkConnector(BaseSIEMConnector):
    """Splunk SIEM connector using HEC (HTTP Event Collector)"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.hec_url = f"https://{config['host']}:{config['port']}/services/collector/event"
        self.token = config['token']
        self.index = config.get('index', 'main')
        self.source = config.get('source', 'nsm')
        self.sourcetype = config.get('sourcetype', 'nsm:event')
        
        # Configure session with retries
        self.session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Set headers
        self.session.headers.update({
            'Authorization': f'Splunk {self.token}',
            'Content-Type': 'application/json'
        })
    
    async def send_event(self, event: SIEMEvent) -> bool:
        """Send single event to Splunk"""
        try:
            payload = {
                'time': event.timestamp.timestamp(),
                'index': self.index,
                'source': self.source,
                'sourcetype': self.sourcetype,
                'event': event.to_dict()
            }
            
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None,
                lambda: self.session.post(
                    self.hec_url,
                    json=payload,
                    timeout=30,
                    verify=self.config.get('verify_ssl', True)
                )
            )
            
            if response.status_code == 200:
                self.logger.debug(f"Successfully sent event {event.event_id} to Splunk")
                return True
            else:
                self.logger.error(f"Failed to send event to Splunk: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error sending event to Splunk: {e}")
            return False
    
    async def send_events_batch(self, events: List[SIEMEvent]) -> Dict[str, Any]:
        """Send multiple events to Splunk in batch"""
        try:
            # Prepare batch payload
            batch_payload = []
            for event in events:
                payload = {
                    'time': event.timestamp.timestamp(),
                    'index': self.index,
                    'source': self.source,
                    'sourcetype': self.sourcetype,
                    'event': event.to_dict()
                }
                batch_payload.append(json.dumps(payload))
            
            # Join payloads with newlines for batch submission
            batch_data = '\n'.join(batch_payload)
            
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None,
                lambda: self.session.post(
                    self.hec_url,
                    data=batch_data,
                    timeout=60,
                    verify=self.config.get('verify_ssl', True)
                )
            )
            
            if response.status_code == 200:
                self.logger.info(f"Successfully sent {len(events)} events to Splunk")
                return {
                    'success': True,
                    'events_sent': len(events),
                    'response': response.json()
                }
            else:
                self.logger.error(f"Failed to send batch to Splunk: {response.status_code} - {response.text}")
                return {
                    'success': False,
                    'events_sent': 0,
                    'error': f"HTTP {response.status_code}: {response.text}"
                }
                
        except Exception as e:
            self.logger.error(f"Error sending batch to Splunk: {e}")
            return {
                'success': False,
                'events_sent': 0,
                'error': str(e)
            }
    
    async def test_connection(self) -> bool:
        """Test connection to Splunk HEC"""
        try:
            test_payload = {
                'time': time.time(),
                'index': self.index,
                'source': self.source,
                'sourcetype': 'test',
                'event': {'message': 'Connection test from NSM SIEM Integration'}
            }
            
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None,
                lambda: self.session.post(
                    self.hec_url,
                    json=test_payload,
                    timeout=10,
                    verify=self.config.get('verify_ssl', True)
                )
            )
            
            return response.status_code == 200
            
        except Exception as e:
            self.logger.error(f"Splunk connection test failed: {e}")
            return False


class ElasticStackConnector(BaseSIEMConnector):
    """Elasticsearch/Elastic Stack connector"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        
        # Initialize Elasticsearch client
        es_config = {
            'hosts': config['hosts'],
            'timeout': config.get('timeout', 30),
            'max_retries': config.get('max_retries', 3),
            'retry_on_timeout': True
        }
        
        # Add authentication if configured
        if config.get('username') and config.get('password'):
            es_config['http_auth'] = (config['username'], config['password'])
        
        # SSL configuration
        if config.get('use_ssl', False):
            es_config['use_ssl'] = True
            es_config['verify_certs'] = config.get('verify_certs', True)
            if config.get('ca_certs'):
                es_config['ca_certs'] = config['ca_certs']
        
        self.es_client = Elasticsearch(**es_config)
        self.index_pattern = config.get('index_pattern', 'nsm-events-%Y-%m-%d')
        self.doc_type = config.get('doc_type', '_doc')
    
    def _get_index_name(self, timestamp: datetime) -> str:
        """Generate index name based on timestamp"""
        return timestamp.strftime(self.index_pattern)
    
    async def send_event(self, event: SIEMEvent) -> bool:
        """Send single event to Elasticsearch"""
        try:
            index_name = self._get_index_name(event.timestamp)
            
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None,
                lambda: self.es_client.index(
                    index=index_name,
                    doc_type=self.doc_type,
                    id=event.event_id,
                    body=event.to_dict()
                )
            )
            
            if response.get('result') in ['created', 'updated']:
                self.logger.debug(f"Successfully sent event {event.event_id} to Elasticsearch")
                return True
            else:
                self.logger.error(f"Failed to send event to Elasticsearch: {response}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error sending event to Elasticsearch: {e}")
            return False
    
    async def send_events_batch(self, events: List[SIEMEvent]) -> Dict[str, Any]:
        """Send multiple events to Elasticsearch using bulk API"""
        try:
            # Prepare bulk actions
            actions = []
            for event in events:
                index_name = self._get_index_name(event.timestamp)
                action = {
                    '_index': index_name,
                    '_type': self.doc_type,
                    '_id': event.event_id,
                    '_source': event.to_dict()
                }
                actions.append(action)
            
            # Execute bulk operation
            loop = asyncio.get_event_loop()
            success_count, failed_items = await loop.run_in_executor(
                None,
                lambda: bulk(self.es_client, actions, index=None, doc_type=None)
            )
            
            self.logger.info(f"Successfully sent {success_count} events to Elasticsearch")
            
            return {
                'success': True,
                'events_sent': success_count,
                'failed_events': len(failed_items) if failed_items else 0,
                'failed_items': failed_items
            }
            
        except Exception as e:
            self.logger.error(f"Error sending batch to Elasticsearch: {e}")
            return {
                'success': False,
                'events_sent': 0,
                'error': str(e)
            }
    
    async def test_connection(self) -> bool:
        """Test connection to Elasticsearch"""
        try:
            loop = asyncio.get_event_loop()
            info = await loop.run_in_executor(None, self.es_client.info)
            return info and 'cluster_name' in info
            
        except Exception as e:
            self.logger.error(f"Elasticsearch connection test failed: {e}")
            return False


class QRadarConnector(BaseSIEMConnector):
    """IBM QRadar SIEM connector"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.api_url = f"https://{config['host']}/api/siem/offenses"
        self.sec_token = config['sec_token']
        self.version = config.get('version', '12.0')
        
        # Configure session
        self.session = requests.Session()
        self.session.headers.update({
            'SEC': self.sec_token,
            'Version': self.version,
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        })
        
        # Configure retries
        retry_strategy = Retry(total=3, backoff_factor=1)
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("https://", adapter)
    
    async def send_event(self, event: SIEMEvent) -> bool:
        """Send event to QRadar (create offense if needed)"""
        try:
            # QRadar works with offenses, so we convert events to offense data
            offense_data = {
                'description': event.title,
                'severity': self._severity_to_qradar(event.severity),
                'source_network': event.metadata.get('src_ip'),
                'destination_network': event.metadata.get('dst_ip'),
                'categories': [event.event_type],
                'status': 'OPEN'
            }
            
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None,
                lambda: self.session.post(
                    self.api_url,
                    json=offense_data,
                    timeout=30,
                    verify=self.config.get('verify_ssl', True)
                )
            )
            
            if response.status_code in [200, 201]:
                self.logger.debug(f"Successfully sent event {event.event_id} to QRadar")
                return True
            else:
                self.logger.error(f"Failed to send event to QRadar: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error sending event to QRadar: {e}")
            return False
    
    async def send_events_batch(self, events: List[SIEMEvent]) -> Dict[str, Any]:
        """Send multiple events to QRadar"""
        success_count = 0
        failed_count = 0
        
        for event in events:
            if await self.send_event(event):
                success_count += 1
            else:
                failed_count += 1
        
        return {
            'success': success_count > 0,
            'events_sent': success_count,
            'failed_events': failed_count
        }
    
    def _severity_to_qradar(self, severity: str) -> int:
        """Convert severity to QRadar scale"""
        severity_map = {
            'critical': 10,
            'high': 8,
            'medium': 5,
            'low': 3,
            'info': 1
        }
        return severity_map.get(severity.lower(), 5)
    
    async def test_connection(self) -> bool:
        """Test connection to QRadar"""
        try:
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None,
                lambda: self.session.get(
                    f"https://{self.config['host']}/api/system/about",
                    timeout=10,
                    verify=self.config.get('verify_ssl', True)
                )
            )
            
            return response.status_code == 200
            
        except Exception as e:
            self.logger.error(f"QRadar connection test failed: {e}")
            return False


class SyslogConnector(BaseSIEMConnector):
    """Generic Syslog connector for SIEM platforms that accept syslog"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.syslog_server = config['server']
        self.syslog_port = config.get('port', 514)
        self.facility = config.get('facility', 16)  # Local0
        self.protocol = config.get('protocol', 'UDP').upper()
        
    async def send_event(self, event: SIEMEvent) -> bool:
        """Send event via syslog"""
        try:
            # Convert to syslog format
            priority = self.facility * 8 + self._severity_to_syslog(event.severity)
            timestamp = event.timestamp.strftime('%b %d %H:%M:%S')
            hostname = self.config.get('hostname', 'nsm-integration')
            tag = 'NSM'
            
            message = f"<{priority}>{timestamp} {hostname} {tag}: {event.to_cef()}"
            
            if self.protocol == 'UDP':
                await self._send_udp(message)
            elif self.protocol == 'TCP':
                await self._send_tcp(message)
            else:
                raise ValueError(f"Unsupported protocol: {self.protocol}")
            
            self.logger.debug(f"Successfully sent event {event.event_id} via syslog")
            return True
            
        except Exception as e:
            self.logger.error(f"Error sending event via syslog: {e}")
            return False
    
    async def _send_udp(self, message: str):
        """Send syslog message via UDP"""
        loop = asyncio.get_event_loop()
        transport, protocol = await loop.create_datagram_endpoint(
            lambda: asyncio.DatagramProtocol(),
            remote_addr=(self.syslog_server, self.syslog_port)
        )
        transport.sendto(message.encode('utf-8'))
        transport.close()
    
    async def _send_tcp(self, message: str):
        """Send syslog message via TCP"""
        reader, writer = await asyncio.open_connection(
            self.syslog_server, self.syslog_port
        )
        writer.write(f"{message}\n".encode('utf-8'))
        await writer.drain()
        writer.close()
        await writer.wait_closed()
    
    def _severity_to_syslog(self, severity: str) -> int:
        """Convert severity to syslog severity level"""
        severity_map = {
            'critical': 2,  # Critical
            'high': 3,      # Error
            'medium': 4,    # Warning
            'low': 5,       # Notice
            'info': 6       # Informational
        }
        return severity_map.get(severity.lower(), 6)
    
    async def send_events_batch(self, events: List[SIEMEvent]) -> Dict[str, Any]:
        """Send multiple events via syslog"""
        success_count = 0
        failed_count = 0
        
        for event in events:
            if await self.send_event(event):
                success_count += 1
            else:
                failed_count += 1
        
        return {
            'success': success_count > 0,
            'events_sent': success_count,
            'failed_events': failed_count
        }
    
    async def test_connection(self) -> bool:
        """Test syslog connection"""
        try:
            test_message = f"<{self.facility * 8 + 6}>{datetime.now().strftime('%b %d %H:%M:%S')} nsm-test NSM: Connection test"
            
            if self.protocol == 'UDP':
                await self._send_udp(test_message)
            else:
                await self._send_tcp(test_message)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Syslog connection test failed: {e}")
            return False


class SIEMIntegrationEngine:
    """Main SIEM integration engine"""
    
    def __init__(self, config_path: str = "/etc/nsm/siem-integration.yaml"):
        self.config_path = config_path
        self.config = self._load_config()
        self.logger = self._setup_logging()
        
        # Initialize components
        self.redis_client = self._init_redis()
        self.database = self._init_database()
        self.connectors = self._init_connectors()
        
        # Processing settings
        self.batch_size = self.config.get('processing', {}).get('batch_size', 100)
        self.processing_interval = self.config.get('processing', {}).get('interval', 30)
        self.max_retries = self.config.get('processing', {}).get('max_retries', 3)
        
        # Event queues
        self.event_queue = asyncio.Queue(maxsize=10000)
        self.failed_events = []
        
        # Statistics
        self.stats = {
            'events_processed': 0,
            'events_sent': 0,
            'events_failed': 0,
            'last_processing_time': None,
            'connector_stats': {}
        }
        
        # Threading
        self.executor = ThreadPoolExecutor(max_workers=4)
        
        # Control flags
        self.running = False
        self.shutdown_event = asyncio.Event()
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from YAML file"""
        try:
            with open(self.config_path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            print(f"Error loading config: {e}")
            return {}
    
    def _setup_logging(self) -> logging.Logger:
        """Setup logging configuration"""
        logger = logging.getLogger('SIEMIntegrationEngine')
        logger.setLevel(getattr(logging, self.config.get('general', {}).get('log_level', 'INFO')))
        
        # Console handler
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        
        return logger
    
    def _init_redis(self) -> Optional[redis.Redis]:
        """Initialize Redis connection"""
        try:
            redis_config = self.config.get('redis', {})
            if not redis_config.get('enabled', False):
                return None
                
            return redis.Redis(
                host=redis_config['host'],
                port=redis_config['port'],
                db=redis_config.get('db', 0),
                password=redis_config.get('password'),
                decode_responses=True,
                socket_timeout=30,
                socket_connect_timeout=30,
                retry_on_timeout=True,
                max_connections=20
            )
            
        except Exception as e:
            self.logger.error(f"Failed to initialize Redis: {e}")
            return None
    
    def _init_database(self) -> Optional[sqlite3.Connection]:
        """Initialize SQLite database for event tracking"""
        try:
            db_config = self.config.get('database', {})
            db_path = db_config.get('path', '/var/lib/nsm/siem_integration.db')
            
            # Create directory if it doesn't exist
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)
            
            conn = sqlite3.connect(db_path, check_same_thread=False)
            conn.execute('''
                CREATE TABLE IF NOT EXISTS siem_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT UNIQUE,
                    timestamp DATETIME,
                    source TEXT,
                    event_type TEXT,
                    severity TEXT,
                    title TEXT,
                    sent_to_siem BOOLEAN DEFAULT FALSE,
                    retry_count INTEGER DEFAULT 0,
                    last_retry DATETIME,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            conn.execute('''
                CREATE TABLE IF NOT EXISTS connector_status (
                    connector_name TEXT PRIMARY KEY,
                    status TEXT,
                    last_check DATETIME,
                    events_sent INTEGER DEFAULT 0,
                    events_failed INTEGER DEFAULT 0,
                    error_message TEXT
                )
            ''')
            
            conn.commit()
            return conn
            
        except Exception as e:
            self.logger.error(f"Failed to initialize database: {e}")
            return None
    
    def _init_connectors(self) -> Dict[str, BaseSIEMConnector]:
        """Initialize SIEM connectors"""
        connectors = {}
        
        siem_config = self.config.get('siem_platforms', {})
        
        # Splunk connector
        if siem_config.get('splunk', {}).get('enabled', False):
            try:
                connectors['splunk'] = SplunkConnector(siem_config['splunk'])
                self.logger.info("Initialized Splunk connector")
            except Exception as e:
                self.logger.error(f"Failed to initialize Splunk connector: {e}")
        
        # Elasticsearch connector
        if siem_config.get('elasticsearch', {}).get('enabled', False):
            try:
                connectors['elasticsearch'] = ElasticStackConnector(siem_config['elasticsearch'])
                self.logger.info("Initialized Elasticsearch connector")
            except Exception as e:
                self.logger.error(f"Failed to initialize Elasticsearch connector: {e}")
        
        # QRadar connector
        if siem_config.get('qradar', {}).get('enabled', False):
            try:
                connectors['qradar'] = QRadarConnector(siem_config['qradar'])
                self.logger.info("Initialized QRadar connector")
            except Exception as e:
                self.logger.error(f"Failed to initialize QRadar connector: {e}")
        
        # Syslog connector
        if siem_config.get('syslog', {}).get('enabled', False):
            try:
                connectors['syslog'] = SyslogConnector(siem_config['syslog'])
                self.logger.info("Initialized Syslog connector")
            except Exception as e:
                self.logger.error(f"Failed to initialize Syslog connector: {e}")
        
        return connectors
    
    async def add_event(self, event_data: Dict[str, Any]) -> bool:
        """Add event to processing queue"""
        try:
            # Convert to SIEMEvent
            event = SIEMEvent(
                event_id=event_data['event_id'],
                timestamp=datetime.fromisoformat(event_data['timestamp']) if isinstance(event_data['timestamp'], str) else event_data['timestamp'],
                source=event_data['source'],
                event_type=event_data['event_type'],
                severity=event_data['severity'],
                title=event_data['title'],
                description=event_data['description'],
                raw_data=event_data.get('raw_data', {}),
                metadata=event_data.get('metadata', {}),
                enrichment=event_data.get('enrichment', {})
            )
            
            # Add to queue
            await self.event_queue.put(event)
            
            # Store in database for tracking
            if self.database:
                cursor = self.database.cursor()
                cursor.execute('''
                    INSERT OR REPLACE INTO siem_events 
                    (event_id, timestamp, source, event_type, severity, title)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    event.event_id,
                    event.timestamp,
                    event.source,
                    event.event_type,
                    event.severity,
                    event.title
                ))
                self.database.commit()
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error adding event to queue: {e}")
            return False
    
    async def process_events(self):
        """Main event processing loop"""
        self.logger.info("Starting event processing loop")
        
        while self.running:
            try:
                # Collect batch of events
                events = []
                batch_timeout = 0.1  # 100ms timeout for batch collection
                
                try:
                    # Get first event (blocking)
                    event = await asyncio.wait_for(
                        self.event_queue.get(),
                        timeout=self.processing_interval
                    )
                    events.append(event)
                    
                    # Collect additional events for batch (non-blocking)
                    while len(events) < self.batch_size:
                        try:
                            event = await asyncio.wait_for(
                                self.event_queue.get(),
                                timeout=batch_timeout
                            )
                            events.append(event)
                        except asyncio.TimeoutError:
                            break
                            
                except asyncio.TimeoutError:
                    # No events to process, continue
                    continue
                
                if events:
                    await self._process_event_batch(events)
                    self.stats['events_processed'] += len(events)
                    self.stats['last_processing_time'] = datetime.utcnow()
                
            except Exception as e:
                self.logger.error(f"Error in event processing loop: {e}")
                await asyncio.sleep(1)
    
    async def _process_event_batch(self, events: List[SIEMEvent]):
        """Process a batch of events"""
        self.logger.debug(f"Processing batch of {len(events)} events")
        
        # Send to all configured connectors
        for connector_name, connector in self.connectors.items():
            if not connector.enabled:
                continue
            
            try:
                result = await connector.send_events_batch(events)
                
                if result['success']:
                    self.stats['events_sent'] += result['events_sent']
                    self.logger.debug(f"Successfully sent {result['events_sent']} events to {connector_name}")
                    
                    # Update connector stats in database
                    if self.database:
                        cursor = self.database.cursor()
                        cursor.execute('''
                            INSERT OR REPLACE INTO connector_status 
                            (connector_name, status, last_check, events_sent)
                            VALUES (?, 'active', ?, COALESCE((SELECT events_sent FROM connector_status WHERE connector_name = ?), 0) + ?)
                        ''', (connector_name, datetime.utcnow(), connector_name, result['events_sent']))
                        self.database.commit()
                else:
                    self.stats['events_failed'] += len(events)
                    self.logger.error(f"Failed to send events to {connector_name}: {result.get('error', 'Unknown error')}")
                    
                    # Update connector status
                    if self.database:
                        cursor = self.database.cursor()
                        cursor.execute('''
                            INSERT OR REPLACE INTO connector_status 
                            (connector_name, status, last_check, events_failed, error_message)
                            VALUES (?, 'error', ?, COALESCE((SELECT events_failed FROM connector_status WHERE connector_name = ?), 0) + ?, ?)
                        ''', (connector_name, datetime.utcnow(), connector_name, len(events), result.get('error', 'Unknown error')))
                        self.database.commit()
                
            except Exception as e:
                self.logger.error(f"Error sending events to {connector_name}: {e}")
                self.stats['events_failed'] += len(events)
    
    async def monitor_connectors(self):
        """Monitor connector health"""
        while self.running:
            try:
                for connector_name, connector in self.connectors.items():
                    if not connector.enabled:
                        continue
                        
                    health_status = await connector.health_check()
                    
                    # Update stats
                    self.stats['connector_stats'][connector_name] = health_status
                    
                    # Log status changes
                    if health_status['status'] != 'healthy':
                        self.logger.warning(f"Connector {connector_name} is unhealthy: {health_status}")
                    
                # Wait before next check
                await asyncio.sleep(300)  # Check every 5 minutes
                
            except Exception as e:
                self.logger.error(f"Error monitoring connectors: {e}")
                await asyncio.sleep(60)
    
    async def process_redis_events(self):
        """Process events from Redis queue"""
        if not self.redis_client:
            return
        
        self.logger.info("Starting Redis event processing")
        
        while self.running:
            try:
                # Get events from Redis queue
                event_data = self.redis_client.blpop(['nsm:siem_events'], timeout=30)
                
                if event_data:
                    _, event_json = event_data
                    event_dict = json.loads(event_json)
                    await self.add_event(event_dict)
                
            except Exception as e:
                self.logger.error(f"Error processing Redis events: {e}")
                await asyncio.sleep(1)
    
    async def start(self):
        """Start the SIEM integration engine"""
        self.logger.info("Starting SIEM Integration Engine")
        self.running = True
        
        # Start background tasks
        tasks = [
            asyncio.create_task(self.process_events()),
            asyncio.create_task(self.monitor_connectors()),
        ]
        
        # Add Redis processing if configured
        if self.redis_client:
            tasks.append(asyncio.create_task(self.process_redis_events()))
        
        try:
            # Wait for shutdown signal
            await self.shutdown_event.wait()
        finally:
            # Cancel all tasks
            for task in tasks:
                task.cancel()
            
            # Wait for tasks to complete
            await asyncio.gather(*tasks, return_exceptions=True)
            
            # Cleanup
            if self.database:
                self.database.close()
            
            if self.redis_client:
                self.redis_client.close()
            
            self.executor.shutdown(wait=True)
    
    def stop(self):
        """Stop the SIEM integration engine"""
        self.logger.info("Stopping SIEM Integration Engine")
        self.running = False
        self.shutdown_event.set()
    
    def get_stats(self) -> Dict[str, Any]:
        """Get current statistics"""
        return {
            'runtime_stats': self.stats,
            'queue_size': self.event_queue.qsize(),
            'connectors': {name: connector.enabled for name, connector in self.connectors.items()},
            'failed_events_count': len(self.failed_events)
        }


async def main():
    """Main entry point"""
    import signal
    
    # Initialize engine
    engine = SIEMIntegrationEngine()
    
    # Setup signal handlers
    def signal_handler(signum, frame):
        print(f"Received signal {signum}, shutting down...")
        engine.stop()
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Start the engine
    await engine.start()


if __name__ == "__main__":
    asyncio.run(main())