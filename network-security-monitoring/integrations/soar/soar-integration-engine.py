#!/usr/bin/env python3
"""
iSECTECH SOAR Integration Engine
Production-grade SOAR (Security Orchestration, Automation and Response) integration

This engine provides comprehensive integration with SOAR platforms including
Phantom, Demisto/XSOAR, Microsoft Sentinel, and custom SOAR solutions.
"""

import asyncio
import json
import logging
import sqlite3
import uuid
from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union
from pathlib import Path
from enum import Enum

import aiohttp
import redis
import yaml
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


class PlaybookStatus(Enum):
    """Playbook execution status"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class IncidentSeverity(Enum):
    """Incident severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class SOARIncident:
    """Standardized SOAR incident structure"""
    incident_id: str
    title: str
    description: str
    severity: IncidentSeverity
    source: str
    timestamp: datetime
    artifacts: List[Dict[str, Any]]
    metadata: Dict[str, Any]
    enrichment: Dict[str, Any]
    playbooks: List[str]
    status: str = "new"
    assigned_to: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format"""
        data = asdict(self)
        data['timestamp'] = self.timestamp.isoformat()
        data['severity'] = self.severity.value
        return data


@dataclass
class PlaybookExecution:
    """Playbook execution tracking"""
    execution_id: str
    incident_id: str
    playbook_name: str
    status: PlaybookStatus
    start_time: datetime
    end_time: Optional[datetime] = None
    results: Dict[str, Any] = None
    error_message: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format"""
        data = asdict(self)
        data['start_time'] = self.start_time.isoformat()
        data['end_time'] = self.end_time.isoformat() if self.end_time else None
        data['status'] = self.status.value
        return data


class BaseSOARConnector(ABC):
    """Abstract base class for SOAR connectors"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.name = config.get('name', 'unknown')
        self.enabled = config.get('enabled', False)
        self.logger = logging.getLogger(f"{self.__class__.__name__}")
        
    @abstractmethod
    async def create_incident(self, incident: SOARIncident) -> Dict[str, Any]:
        """Create incident in SOAR platform"""
        pass
    
    @abstractmethod
    async def execute_playbook(self, incident_id: str, playbook_name: str, parameters: Dict[str, Any] = None) -> Dict[str, Any]:
        """Execute playbook for incident"""
        pass
    
    @abstractmethod
    async def get_playbook_status(self, execution_id: str) -> Dict[str, Any]:
        """Get playbook execution status"""
        pass
    
    @abstractmethod
    async def update_incident(self, incident_id: str, updates: Dict[str, Any]) -> Dict[str, Any]:
        """Update incident information"""
        pass
    
    @abstractmethod
    async def test_connection(self) -> bool:
        """Test connectivity to SOAR platform"""
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


class PhantomConnector(BaseSOARConnector):
    """Splunk Phantom SOAR connector"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.base_url = f"https://{config['host']}/rest"
        self.auth_token = config['auth_token']
        
        # Configure session
        self.session = requests.Session()
        self.session.headers.update({
            'ph-auth-token': self.auth_token,
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        })
        
        # Configure retries
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("https://", adapter)
    
    async def create_incident(self, incident: SOARIncident) -> Dict[str, Any]:
        """Create incident in Phantom"""
        try:
            # Prepare container data
            container_data = {
                'name': incident.title,
                'description': incident.description,
                'label': incident.source,
                'severity': self._severity_to_phantom(incident.severity),
                'status': 'new',
                'source_data_identifier': incident.incident_id,
                'data': incident.metadata
            }
            
            # Create container
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None,
                lambda: self.session.post(
                    f"{self.base_url}/container",
                    json=container_data,
                    timeout=30,
                    verify=self.config.get('verify_ssl', True)
                )
            )
            
            if response.status_code in [200, 201]:
                container_response = response.json()
                container_id = container_response['id']
                
                # Add artifacts
                for artifact_data in incident.artifacts:
                    await self._create_artifact(container_id, artifact_data)
                
                self.logger.info(f"Successfully created incident {incident.incident_id} in Phantom")
                return {
                    'success': True,
                    'phantom_container_id': container_id,
                    'message': 'Incident created successfully'
                }
            else:
                self.logger.error(f"Failed to create incident in Phantom: {response.status_code} - {response.text}")
                return {
                    'success': False,
                    'error': f"HTTP {response.status_code}: {response.text}"
                }
                
        except Exception as e:
            self.logger.error(f"Error creating incident in Phantom: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    async def _create_artifact(self, container_id: int, artifact_data: Dict[str, Any]) -> bool:
        """Create artifact in Phantom container"""
        try:
            artifact_payload = {
                'container_id': container_id,
                'name': artifact_data.get('name', 'NSM Artifact'),
                'description': artifact_data.get('description', ''),
                'type': artifact_data.get('type', 'network'),
                'cef': artifact_data.get('cef', {}),
                'source_data_identifier': artifact_data.get('id', str(uuid.uuid4()))
            }
            
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None,
                lambda: self.session.post(
                    f"{self.base_url}/artifact",
                    json=artifact_payload,
                    timeout=30,
                    verify=self.config.get('verify_ssl', True)
                )
            )
            
            return response.status_code in [200, 201]
            
        except Exception as e:
            self.logger.error(f"Error creating artifact in Phantom: {e}")
            return False
    
    async def execute_playbook(self, incident_id: str, playbook_name: str, parameters: Dict[str, Any] = None) -> Dict[str, Any]:
        """Execute playbook in Phantom"""
        try:
            # First, get the container ID from incident ID
            container_id = await self._get_container_id(incident_id)
            if not container_id:
                return {
                    'success': False,
                    'error': 'Container not found for incident'
                }
            
            # Get playbook ID
            playbook_id = await self._get_playbook_id(playbook_name)
            if not playbook_id:
                return {
                    'success': False,
                    'error': f'Playbook {playbook_name} not found'
                }
            
            # Execute playbook
            execution_data = {
                'container_id': container_id,
                'playbook_id': playbook_id,
                'scope': 'all',
                'run_data': parameters or {}
            }
            
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None,
                lambda: self.session.post(
                    f"{self.base_url}/playbook_run",
                    json=execution_data,
                    timeout=30,
                    verify=self.config.get('verify_ssl', True)
                )
            )
            
            if response.status_code in [200, 201]:
                execution_response = response.json()
                self.logger.info(f"Successfully executed playbook {playbook_name} for incident {incident_id}")
                return {
                    'success': True,
                    'execution_id': execution_response.get('playbook_run_id'),
                    'message': f'Playbook {playbook_name} executed successfully'
                }
            else:
                self.logger.error(f"Failed to execute playbook in Phantom: {response.status_code} - {response.text}")
                return {
                    'success': False,
                    'error': f"HTTP {response.status_code}: {response.text}"
                }
                
        except Exception as e:
            self.logger.error(f"Error executing playbook in Phantom: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    async def _get_container_id(self, incident_id: str) -> Optional[int]:
        """Get Phantom container ID from incident ID"""
        try:
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None,
                lambda: self.session.get(
                    f"{self.base_url}/container",
                    params={'_filter_source_data_identifier': f'"{incident_id}"'},
                    timeout=30,
                    verify=self.config.get('verify_ssl', True)
                )
            )
            
            if response.status_code == 200:
                containers = response.json().get('data', [])
                if containers:
                    return containers[0]['id']
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error getting container ID: {e}")
            return None
    
    async def _get_playbook_id(self, playbook_name: str) -> Optional[int]:
        """Get Phantom playbook ID from name"""
        try:
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None,
                lambda: self.session.get(
                    f"{self.base_url}/playbook",
                    params={'_filter_name': f'"{playbook_name}"'},
                    timeout=30,
                    verify=self.config.get('verify_ssl', True)
                )
            )
            
            if response.status_code == 200:
                playbooks = response.json().get('data', [])
                if playbooks:
                    return playbooks[0]['id']
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error getting playbook ID: {e}")
            return None
    
    async def get_playbook_status(self, execution_id: str) -> Dict[str, Any]:
        """Get playbook execution status in Phantom"""
        try:
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None,
                lambda: self.session.get(
                    f"{self.base_url}/playbook_run/{execution_id}",
                    timeout=30,
                    verify=self.config.get('verify_ssl', True)
                )
            )
            
            if response.status_code == 200:
                execution_data = response.json()
                return {
                    'success': True,
                    'status': execution_data.get('status', 'unknown'),
                    'message': execution_data.get('message', ''),
                    'results': execution_data.get('result_data', {})
                }
            else:
                return {
                    'success': False,
                    'error': f"HTTP {response.status_code}: {response.text}"
                }
                
        except Exception as e:
            self.logger.error(f"Error getting playbook status in Phantom: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    async def update_incident(self, incident_id: str, updates: Dict[str, Any]) -> Dict[str, Any]:
        """Update incident in Phantom"""
        try:
            container_id = await self._get_container_id(incident_id)
            if not container_id:
                return {
                    'success': False,
                    'error': 'Container not found for incident'
                }
            
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None,
                lambda: self.session.post(
                    f"{self.base_url}/container/{container_id}",
                    json=updates,
                    timeout=30,
                    verify=self.config.get('verify_ssl', True)
                )
            )
            
            if response.status_code == 200:
                return {
                    'success': True,
                    'message': 'Incident updated successfully'
                }
            else:
                return {
                    'success': False,
                    'error': f"HTTP {response.status_code}: {response.text}"
                }
                
        except Exception as e:
            self.logger.error(f"Error updating incident in Phantom: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def _severity_to_phantom(self, severity: IncidentSeverity) -> str:
        """Convert severity to Phantom format"""
        severity_map = {
            IncidentSeverity.CRITICAL: 'high',
            IncidentSeverity.HIGH: 'high',
            IncidentSeverity.MEDIUM: 'medium',
            IncidentSeverity.LOW: 'low',
            IncidentSeverity.INFO: 'low'
        }
        return severity_map.get(severity, 'medium')
    
    async def test_connection(self) -> bool:
        """Test connection to Phantom"""
        try:
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None,
                lambda: self.session.get(
                    f"{self.base_url}/system_info",
                    timeout=10,
                    verify=self.config.get('verify_ssl', True)
                )
            )
            
            return response.status_code == 200
            
        except Exception as e:
            self.logger.error(f"Phantom connection test failed: {e}")
            return False


class DemistoConnector(BaseSOARConnector):
    """Demisto/XSOAR connector"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.base_url = f"https://{config['host']}"
        self.api_key = config['api_key']
        
        # Configure session
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'Bearer {self.api_key}',
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        })
        
        # Configure retries
        retry_strategy = Retry(total=3, backoff_factor=1)
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("https://", adapter)
    
    async def create_incident(self, incident: SOARIncident) -> Dict[str, Any]:
        """Create incident in Demisto/XSOAR"""
        try:
            incident_data = {
                'name': incident.title,
                'details': incident.description,
                'severity': self._severity_to_demisto(incident.severity),
                'type': incident.source,
                'customFields': {
                    'sourceip': incident.metadata.get('src_ip'),
                    'destinationip': incident.metadata.get('dst_ip'),
                    'nsm_incident_id': incident.incident_id
                },
                'labels': [
                    {'type': 'Source', 'value': incident.source},
                    {'type': 'EventType', 'value': incident.metadata.get('event_type', 'unknown')}
                ]
            }
            
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None,
                lambda: self.session.post(
                    f"{self.base_url}/incident",
                    json=incident_data,
                    timeout=30,
                    verify=self.config.get('verify_ssl', True)
                )
            )
            
            if response.status_code in [200, 201]:
                incident_response = response.json()
                demisto_incident_id = incident_response.get('id')
                
                self.logger.info(f"Successfully created incident {incident.incident_id} in Demisto")
                return {
                    'success': True,
                    'demisto_incident_id': demisto_incident_id,
                    'message': 'Incident created successfully'
                }
            else:
                self.logger.error(f"Failed to create incident in Demisto: {response.status_code} - {response.text}")
                return {
                    'success': False,
                    'error': f"HTTP {response.status_code}: {response.text}"
                }
                
        except Exception as e:
            self.logger.error(f"Error creating incident in Demisto: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    async def execute_playbook(self, incident_id: str, playbook_name: str, parameters: Dict[str, Any] = None) -> Dict[str, Any]:
        """Execute playbook in Demisto/XSOAR"""
        try:
            # Get Demisto incident ID
            demisto_incident_id = await self._get_demisto_incident_id(incident_id)
            if not demisto_incident_id:
                return {
                    'success': False,
                    'error': 'Incident not found in Demisto'
                }
            
            # Execute playbook
            execution_data = {
                'playbookId': playbook_name,
                'incidentId': demisto_incident_id,
                'inputs': parameters or {}
            }
            
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None,
                lambda: self.session.post(
                    f"{self.base_url}/investigation/{demisto_incident_id}/playbook",
                    json=execution_data,
                    timeout=30,
                    verify=self.config.get('verify_ssl', True)
                )
            )
            
            if response.status_code in [200, 201]:
                execution_response = response.json()
                self.logger.info(f"Successfully executed playbook {playbook_name} for incident {incident_id}")
                return {
                    'success': True,
                    'execution_id': execution_response.get('id'),
                    'message': f'Playbook {playbook_name} executed successfully'
                }
            else:
                self.logger.error(f"Failed to execute playbook in Demisto: {response.status_code} - {response.text}")
                return {
                    'success': False,
                    'error': f"HTTP {response.status_code}: {response.text}"
                }
                
        except Exception as e:
            self.logger.error(f"Error executing playbook in Demisto: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    async def _get_demisto_incident_id(self, nsm_incident_id: str) -> Optional[str]:
        """Get Demisto incident ID from NSM incident ID"""
        try:
            # Search for incident by custom field
            search_query = {
                'filter': {
                    'query': f'customFields.nsm_incident_id:"{nsm_incident_id}"'
                }
            }
            
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None,
                lambda: self.session.post(
                    f"{self.base_url}/incidents/search",
                    json=search_query,
                    timeout=30,
                    verify=self.config.get('verify_ssl', True)
                )
            )
            
            if response.status_code == 200:
                incidents = response.json().get('data', [])
                if incidents:
                    return incidents[0]['id']
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error getting Demisto incident ID: {e}")
            return None
    
    async def get_playbook_status(self, execution_id: str) -> Dict[str, Any]:
        """Get playbook execution status in Demisto/XSOAR"""
        try:
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None,
                lambda: self.session.get(
                    f"{self.base_url}/investigation/{execution_id}",
                    timeout=30,
                    verify=self.config.get('verify_ssl', True)
                )
            )
            
            if response.status_code == 200:
                investigation_data = response.json()
                return {
                    'success': True,
                    'status': investigation_data.get('status', 'unknown'),
                    'state': investigation_data.get('state', 'unknown'),
                    'results': investigation_data.get('entries', [])
                }
            else:
                return {
                    'success': False,
                    'error': f"HTTP {response.status_code}: {response.text}"
                }
                
        except Exception as e:
            self.logger.error(f"Error getting playbook status in Demisto: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    async def update_incident(self, incident_id: str, updates: Dict[str, Any]) -> Dict[str, Any]:
        """Update incident in Demisto/XSOAR"""
        try:
            demisto_incident_id = await self._get_demisto_incident_id(incident_id)
            if not demisto_incident_id:
                return {
                    'success': False,
                    'error': 'Incident not found in Demisto'
                }
            
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None,
                lambda: self.session.post(
                    f"{self.base_url}/incident/{demisto_incident_id}",
                    json=updates,
                    timeout=30,
                    verify=self.config.get('verify_ssl', True)
                )
            )
            
            if response.status_code == 200:
                return {
                    'success': True,
                    'message': 'Incident updated successfully'
                }
            else:
                return {
                    'success': False,
                    'error': f"HTTP {response.status_code}: {response.text}"
                }
                
        except Exception as e:
            self.logger.error(f"Error updating incident in Demisto: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def _severity_to_demisto(self, severity: IncidentSeverity) -> int:
        """Convert severity to Demisto numeric scale"""
        severity_map = {
            IncidentSeverity.CRITICAL: 4,
            IncidentSeverity.HIGH: 3,
            IncidentSeverity.MEDIUM: 2,
            IncidentSeverity.LOW: 1,
            IncidentSeverity.INFO: 0.5
        }
        return severity_map.get(severity, 2)
    
    async def test_connection(self) -> bool:
        """Test connection to Demisto/XSOAR"""
        try:
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None,
                lambda: self.session.get(
                    f"{self.base_url}/settings/about",
                    timeout=10,
                    verify=self.config.get('verify_ssl', True)
                )
            )
            
            return response.status_code == 200
            
        except Exception as e:
            self.logger.error(f"Demisto connection test failed: {e}")
            return False


class WebhookConnector(BaseSOARConnector):
    """Generic webhook connector for custom SOAR integrations"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.webhook_url = config['webhook_url']
        self.auth_headers = config.get('auth_headers', {})
        
        # Configure session
        self.session = requests.Session()
        self.session.headers.update({
            'Content-Type': 'application/json',
            **self.auth_headers
        })
    
    async def create_incident(self, incident: SOARIncident) -> Dict[str, Any]:
        """Create incident via webhook"""
        try:
            payload = {
                'action': 'create_incident',
                'incident': incident.to_dict()
            }
            
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None,
                lambda: self.session.post(
                    self.webhook_url,
                    json=payload,
                    timeout=30,
                    verify=self.config.get('verify_ssl', True)
                )
            )
            
            if response.status_code in [200, 201, 202]:
                self.logger.info(f"Successfully sent incident {incident.incident_id} via webhook")
                return {
                    'success': True,
                    'response': response.json() if response.content else {},
                    'message': 'Incident sent successfully'
                }
            else:
                self.logger.error(f"Failed to send incident via webhook: {response.status_code} - {response.text}")
                return {
                    'success': False,
                    'error': f"HTTP {response.status_code}: {response.text}"
                }
                
        except Exception as e:
            self.logger.error(f"Error sending incident via webhook: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    async def execute_playbook(self, incident_id: str, playbook_name: str, parameters: Dict[str, Any] = None) -> Dict[str, Any]:
        """Execute playbook via webhook"""
        try:
            payload = {
                'action': 'execute_playbook',
                'incident_id': incident_id,
                'playbook_name': playbook_name,
                'parameters': parameters or {}
            }
            
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None,
                lambda: self.session.post(
                    self.webhook_url,
                    json=payload,
                    timeout=30,
                    verify=self.config.get('verify_ssl', True)
                )
            )
            
            if response.status_code in [200, 201, 202]:
                response_data = response.json() if response.content else {}
                return {
                    'success': True,
                    'execution_id': response_data.get('execution_id', str(uuid.uuid4())),
                    'message': f'Playbook {playbook_name} execution requested'
                }
            else:
                return {
                    'success': False,
                    'error': f"HTTP {response.status_code}: {response.text}"
                }
                
        except Exception as e:
            self.logger.error(f"Error executing playbook via webhook: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    async def get_playbook_status(self, execution_id: str) -> Dict[str, Any]:
        """Get playbook status (not supported for generic webhook)"""
        return {
            'success': False,
            'error': 'Status monitoring not supported for webhook connector'
        }
    
    async def update_incident(self, incident_id: str, updates: Dict[str, Any]) -> Dict[str, Any]:
        """Update incident via webhook"""
        try:
            payload = {
                'action': 'update_incident',
                'incident_id': incident_id,
                'updates': updates
            }
            
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None,
                lambda: self.session.post(
                    self.webhook_url,
                    json=payload,
                    timeout=30,
                    verify=self.config.get('verify_ssl', True)
                )
            )
            
            if response.status_code in [200, 201, 202]:
                return {
                    'success': True,
                    'message': 'Incident update sent successfully'
                }
            else:
                return {
                    'success': False,
                    'error': f"HTTP {response.status_code}: {response.text}"
                }
                
        except Exception as e:
            self.logger.error(f"Error updating incident via webhook: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    async def test_connection(self) -> bool:
        """Test webhook connection"""
        try:
            payload = {
                'action': 'health_check',
                'timestamp': datetime.utcnow().isoformat()
            }
            
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None,
                lambda: self.session.post(
                    self.webhook_url,
                    json=payload,
                    timeout=10,
                    verify=self.config.get('verify_ssl', True)
                )
            )
            
            return response.status_code in [200, 201, 202]
            
        except Exception as e:
            self.logger.error(f"Webhook connection test failed: {e}")
            return False


class SOARIntegrationEngine:
    """Main SOAR integration engine"""
    
    def __init__(self, config_path: str = "/etc/nsm/soar-integration.yaml"):
        self.config_path = config_path
        self.config = self._load_config()
        self.logger = self._setup_logging()
        
        # Initialize components
        self.redis_client = self._init_redis()
        self.database = self._init_database()
        self.connectors = self._init_connectors()
        
        # Processing settings
        self.processing_interval = self.config.get('processing', {}).get('interval', 30)
        self.max_retries = self.config.get('processing', {}).get('max_retries', 3)
        
        # Incident queue
        self.incident_queue = asyncio.Queue(maxsize=1000)
        
        # Statistics
        self.stats = {
            'incidents_processed': 0,
            'playbooks_executed': 0,
            'incidents_failed': 0,
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
        logger = logging.getLogger('SOARIntegrationEngine')
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
        """Initialize SQLite database for incident tracking"""
        try:
            db_config = self.config.get('database', {})
            db_path = db_config.get('path', '/var/lib/nsm/soar_integration.db')
            
            # Create directory if it doesn't exist
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)
            
            conn = sqlite3.connect(db_path, check_same_thread=False)
            
            # Create incidents table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS soar_incidents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    incident_id TEXT UNIQUE,
                    title TEXT,
                    severity TEXT,
                    source TEXT,
                    timestamp DATETIME,
                    status TEXT DEFAULT 'new',
                    assigned_to TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Create playbook executions table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS playbook_executions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    execution_id TEXT UNIQUE,
                    incident_id TEXT,
                    playbook_name TEXT,
                    status TEXT,
                    start_time DATETIME,
                    end_time DATETIME,
                    results TEXT,
                    error_message TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (incident_id) REFERENCES soar_incidents (incident_id)
                )
            ''')
            
            # Create connector status table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS connector_status (
                    connector_name TEXT PRIMARY KEY,
                    status TEXT,
                    last_check DATETIME,
                    incidents_created INTEGER DEFAULT 0,
                    playbooks_executed INTEGER DEFAULT 0,
                    errors_count INTEGER DEFAULT 0,
                    error_message TEXT
                )
            ''')
            
            conn.commit()
            return conn
            
        except Exception as e:
            self.logger.error(f"Failed to initialize database: {e}")
            return None
    
    def _init_connectors(self) -> Dict[str, BaseSOARConnector]:
        """Initialize SOAR connectors"""
        connectors = {}
        
        soar_config = self.config.get('soar_platforms', {})
        
        # Phantom connector
        if soar_config.get('phantom', {}).get('enabled', False):
            try:
                connectors['phantom'] = PhantomConnector(soar_config['phantom'])
                self.logger.info("Initialized Phantom connector")
            except Exception as e:
                self.logger.error(f"Failed to initialize Phantom connector: {e}")
        
        # Demisto connector
        if soar_config.get('demisto', {}).get('enabled', False):
            try:
                connectors['demisto'] = DemistoConnector(soar_config['demisto'])
                self.logger.info("Initialized Demisto connector")
            except Exception as e:
                self.logger.error(f"Failed to initialize Demisto connector: {e}")
        
        # Webhook connector
        if soar_config.get('webhook', {}).get('enabled', False):
            try:
                connectors['webhook'] = WebhookConnector(soar_config['webhook'])
                self.logger.info("Initialized Webhook connector")
            except Exception as e:
                self.logger.error(f"Failed to initialize Webhook connector: {e}")
        
        return connectors
    
    async def create_incident(self, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create incident in SOAR platforms"""
        try:
            # Convert to SOARIncident
            incident = SOARIncident(
                incident_id=incident_data['incident_id'],
                title=incident_data['title'],
                description=incident_data['description'],
                severity=IncidentSeverity(incident_data['severity']),
                source=incident_data['source'],
                timestamp=datetime.fromisoformat(incident_data['timestamp']) if isinstance(incident_data['timestamp'], str) else incident_data['timestamp'],
                artifacts=incident_data.get('artifacts', []),
                metadata=incident_data.get('metadata', {}),
                enrichment=incident_data.get('enrichment', {}),
                playbooks=incident_data.get('playbooks', []),
                assigned_to=incident_data.get('assigned_to')
            )
            
            # Add to queue
            await self.incident_queue.put(('create', incident))
            
            # Store in database
            if self.database:
                cursor = self.database.cursor()
                cursor.execute('''
                    INSERT OR REPLACE INTO soar_incidents 
                    (incident_id, title, severity, source, timestamp, status, assigned_to)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    incident.incident_id,
                    incident.title,
                    incident.severity.value,
                    incident.source,
                    incident.timestamp,
                    incident.status,
                    incident.assigned_to
                ))
                self.database.commit()
            
            return {
                'success': True,
                'message': 'Incident queued for processing'
            }
            
        except Exception as e:
            self.logger.error(f"Error creating incident: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    async def execute_playbook(self, incident_id: str, playbook_name: str, parameters: Dict[str, Any] = None) -> Dict[str, Any]:
        """Execute playbook for incident"""
        try:
            # Add to queue
            await self.incident_queue.put(('execute_playbook', {
                'incident_id': incident_id,
                'playbook_name': playbook_name,
                'parameters': parameters or {}
            }))
            
            return {
                'success': True,
                'message': 'Playbook execution queued'
            }
            
        except Exception as e:
            self.logger.error(f"Error executing playbook: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    async def process_incidents(self):
        """Main incident processing loop"""
        self.logger.info("Starting incident processing loop")
        
        while self.running:
            try:
                # Get incident from queue
                try:
                    action, data = await asyncio.wait_for(
                        self.incident_queue.get(),
                        timeout=self.processing_interval
                    )
                except asyncio.TimeoutError:
                    continue
                
                if action == 'create':
                    await self._process_incident_creation(data)
                elif action == 'execute_playbook':
                    await self._process_playbook_execution(data)
                
                self.stats['last_processing_time'] = datetime.utcnow()
                
            except Exception as e:
                self.logger.error(f"Error in incident processing loop: {e}")
                await asyncio.sleep(1)
    
    async def _process_incident_creation(self, incident: SOARIncident):
        """Process incident creation"""
        self.logger.debug(f"Processing incident creation: {incident.incident_id}")
        
        # Send to all configured connectors
        for connector_name, connector in self.connectors.items():
            if not connector.enabled:
                continue
            
            try:
                result = await connector.create_incident(incident)
                
                if result['success']:
                    self.stats['incidents_processed'] += 1
                    self.logger.info(f"Successfully created incident {incident.incident_id} in {connector_name}")
                    
                    # Execute associated playbooks
                    for playbook_name in incident.playbooks:
                        await self._execute_playbook_for_incident(
                            incident.incident_id,
                            playbook_name,
                            connector_name,
                            connector
                        )
                    
                    # Update connector stats
                    if self.database:
                        cursor = self.database.cursor()
                        cursor.execute('''
                            INSERT OR REPLACE INTO connector_status 
                            (connector_name, status, last_check, incidents_created)
                            VALUES (?, 'active', ?, COALESCE((SELECT incidents_created FROM connector_status WHERE connector_name = ?), 0) + 1)
                        ''', (connector_name, datetime.utcnow(), connector_name))
                        self.database.commit()
                else:
                    self.stats['incidents_failed'] += 1
                    self.logger.error(f"Failed to create incident {incident.incident_id} in {connector_name}: {result.get('error', 'Unknown error')}")
                    
            except Exception as e:
                self.logger.error(f"Error creating incident in {connector_name}: {e}")
                self.stats['incidents_failed'] += 1
    
    async def _process_playbook_execution(self, data: Dict[str, Any]):
        """Process playbook execution"""
        incident_id = data['incident_id']
        playbook_name = data['playbook_name']
        parameters = data['parameters']
        
        self.logger.debug(f"Processing playbook execution: {playbook_name} for incident {incident_id}")
        
        # Execute on all connectors
        for connector_name, connector in self.connectors.items():
            if not connector.enabled:
                continue
            
            await self._execute_playbook_for_incident(
                incident_id,
                playbook_name,
                connector_name,
                connector,
                parameters
            )
    
    async def _execute_playbook_for_incident(self, incident_id: str, playbook_name: str, connector_name: str, connector: BaseSOARConnector, parameters: Dict[str, Any] = None):
        """Execute playbook for incident on specific connector"""
        try:
            execution_id = str(uuid.uuid4())
            
            # Store execution record
            if self.database:
                cursor = self.database.cursor()
                cursor.execute('''
                    INSERT INTO playbook_executions 
                    (execution_id, incident_id, playbook_name, status, start_time)
                    VALUES (?, ?, ?, 'running', ?)
                ''', (execution_id, incident_id, playbook_name, datetime.utcnow()))
                self.database.commit()
            
            # Execute playbook
            result = await connector.execute_playbook(incident_id, playbook_name, parameters)
            
            if result['success']:
                self.stats['playbooks_executed'] += 1
                self.logger.info(f"Successfully executed playbook {playbook_name} for incident {incident_id} in {connector_name}")
                
                # Update execution record
                if self.database:
                    cursor = self.database.cursor()
                    cursor.execute('''
                        UPDATE playbook_executions 
                        SET status = 'completed', end_time = ?, results = ?
                        WHERE execution_id = ?
                    ''', (datetime.utcnow(), json.dumps(result), execution_id))
                    self.database.commit()
            else:
                self.logger.error(f"Failed to execute playbook {playbook_name} for incident {incident_id} in {connector_name}: {result.get('error', 'Unknown error')}")
                
                # Update execution record with error
                if self.database:
                    cursor = self.database.cursor()
                    cursor.execute('''
                        UPDATE playbook_executions 
                        SET status = 'failed', end_time = ?, error_message = ?
                        WHERE execution_id = ?
                    ''', (datetime.utcnow(), result.get('error', 'Unknown error'), execution_id))
                    self.database.commit()
                
        except Exception as e:
            self.logger.error(f"Error executing playbook {playbook_name} for incident {incident_id} in {connector_name}: {e}")
    
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
    
    async def process_redis_incidents(self):
        """Process incidents from Redis queue"""
        if not self.redis_client:
            return
        
        self.logger.info("Starting Redis incident processing")
        
        while self.running:
            try:
                # Get incidents from Redis queue
                incident_data = self.redis_client.blpop(['nsm:soar_incidents'], timeout=30)
                
                if incident_data:
                    _, incident_json = incident_data
                    incident_dict = json.loads(incident_json)
                    await self.create_incident(incident_dict)
                
            except Exception as e:
                self.logger.error(f"Error processing Redis incidents: {e}")
                await asyncio.sleep(1)
    
    async def start(self):
        """Start the SOAR integration engine"""
        self.logger.info("Starting SOAR Integration Engine")
        self.running = True
        
        # Start background tasks
        tasks = [
            asyncio.create_task(self.process_incidents()),
            asyncio.create_task(self.monitor_connectors()),
        ]
        
        # Add Redis processing if configured
        if self.redis_client:
            tasks.append(asyncio.create_task(self.process_redis_incidents()))
        
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
        """Stop the SOAR integration engine"""
        self.logger.info("Stopping SOAR Integration Engine")
        self.running = False
        self.shutdown_event.set()
    
    def get_stats(self) -> Dict[str, Any]:
        """Get current statistics"""
        return {
            'runtime_stats': self.stats,
            'queue_size': self.incident_queue.qsize(),
            'connectors': {name: connector.enabled for name, connector in self.connectors.items()}
        }


async def main():
    """Main entry point"""
    import signal
    
    # Initialize engine
    engine = SOARIntegrationEngine()
    
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