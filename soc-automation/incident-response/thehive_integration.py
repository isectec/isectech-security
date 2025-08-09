"""
SOC Automation - TheHive Integration

Integration with TheHive case management platform for incident response.
Provides automated case creation, task management, observable creation,
and case lifecycle management.
"""

import asyncio
import logging
import json
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from enum import Enum
import aiohttp
import structlog

logger = structlog.get_logger(__name__)

class CaseSeverity(Enum):
    """TheHive case severity levels"""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

class CaseStatus(Enum):
    """TheHive case status"""
    OPEN = "Open"
    RESOLVED = "Resolved"
    DELETED = "Deleted"

class TaskStatus(Enum):
    """TheHive task status"""
    WAITING = "Waiting"
    INPROGRESS = "InProgress"
    COMPLETED = "Completed"
    CANCEL = "Cancel"

class ObservableType(Enum):
    """TheHive observable data types"""
    DOMAIN = "domain"
    FILE = "file"
    FILENAME = "filename"
    FQDN = "fqdn"
    HASH = "hash"
    IP = "ip"
    MAIL = "mail"
    MAIL_SUBJECT = "mail_subject"
    OTHER = "other"
    REGEXP = "regexp"
    REGISTRY = "registry"
    URI_PATH = "uri_path"
    URL = "url"
    USER_AGENT = "user_agent"

@dataclass
class TheHiveCase:
    """TheHive case structure"""
    title: str
    description: str
    severity: CaseSeverity = CaseSeverity.MEDIUM
    tags: List[str] = None
    tlp: int = 2  # TLP:AMBER
    customFields: Dict[str, Any] = None
    tasks: List[Dict[str, Any]] = None
    
    # Auto-generated fields
    case_id: str = None
    status: CaseStatus = CaseStatus.OPEN
    created_at: datetime = None
    created_by: str = "soc_automation"

@dataclass
class TheHiveTask:
    """TheHive task structure"""
    title: str
    description: str = ""
    status: TaskStatus = TaskStatus.WAITING
    group: str = "default"
    assignee: str = None
    
    # Auto-generated fields
    task_id: str = None
    case_id: str = None
    created_at: datetime = None

@dataclass
class TheHiveObservable:
    """TheHive observable structure"""
    dataType: ObservableType
    data: str
    message: str = ""
    tags: List[str] = None
    ioc: bool = False
    sighted: bool = False
    
    # Auto-generated fields
    observable_id: str = None
    case_id: str = None
    created_at: datetime = None

class TheHiveIntegration:
    """
    TheHive Case Management Integration
    
    Provides automated integration with TheHive for:
    - Case creation and management
    - Task assignment and tracking
    - Observable creation and enrichment
    - Case lifecycle automation
    - Metrics and reporting
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        
        # TheHive configuration
        self.base_url = config.get('url', 'http://localhost:9000')
        self.api_key = config.get('api_key', '')
        self.organization = config.get('organization', 'default')
        self.verify_ssl = config.get('verify_ssl', True)
        
        # HTTP session
        self.session: aiohttp.ClientSession = None
        
        # Configuration
        self.default_case_template = config.get('default_case_template', 'incident_response')
        self.auto_assign_tasks = config.get('auto_assign_tasks', True)
        self.case_tag_prefix = config.get('case_tag_prefix', 'soc_automation')
        
        # Headers for API requests
        self.headers = {
            'Authorization': f'Bearer {self.api_key}',
            'Content-Type': 'application/json',
            'User-Agent': 'SOC-Automation/1.0'
        }
        
        logger.info("TheHiveIntegration initialized",
                   base_url=self.base_url,
                   organization=self.organization)
    
    async def initialize(self):
        """Initialize TheHive integration"""
        try:
            # Create HTTP session
            connector = aiohttp.TCPConnector(verify_ssl=self.verify_ssl)
            self.session = aiohttp.ClientSession(
                connector=connector,
                headers=self.headers,
                timeout=aiohttp.ClientTimeout(total=30)
            )
            
            # Test connectivity
            await self._test_connection()
            
            logger.info("TheHiveIntegration initialized successfully")
            
        except Exception as e:
            logger.error("Failed to initialize TheHive integration", error=str(e))
            raise
    
    async def close(self):
        """Close HTTP session"""
        if self.session:
            await self.session.close()
    
    async def _test_connection(self):
        """Test connection to TheHive API"""
        try:
            async with self.session.get(f"{self.base_url}/api/v1/status") as response:
                if response.status == 200:
                    status_data = await response.json()
                    logger.info("TheHive connection test successful", 
                               version=status_data.get('version'))
                else:
                    raise Exception(f"API returned status {response.status}")
                    
        except Exception as e:
            logger.error("TheHive connection test failed", error=str(e))
            raise
    
    async def create_case_from_incident(self, incident_context: Dict[str, Any]) -> Optional[str]:
        """
        Create TheHive case from incident context
        
        Args:
            incident_context: Incident context data
            
        Returns:
            TheHive case ID if successful, None otherwise
        """
        try:
            # Extract incident details
            incident_id = incident_context.get('incident_id', 'unknown')
            incident_type = incident_context.get('incident_type', 'security_incident')
            severity = incident_context.get('severity', 'medium')
            alert_data = incident_context.get('alert_data', {})
            
            # Map severity to TheHive severity
            severity_mapping = {
                'low': CaseSeverity.LOW,
                'medium': CaseSeverity.MEDIUM,
                'high': CaseSeverity.HIGH,
                'critical': CaseSeverity.CRITICAL
            }
            
            case_severity = severity_mapping.get(severity.lower(), CaseSeverity.MEDIUM)
            
            # Create case title
            case_title = f"[{incident_type.upper()}] Incident {incident_id[:8]}"
            if 'source_ip' in alert_data:
                case_title += f" - {alert_data['source_ip']}"
            
            # Create case description
            description_parts = [
                f"**Incident ID:** {incident_id}",
                f"**Incident Type:** {incident_type}",
                f"**Severity:** {severity}",
                f"**Created:** {datetime.now(timezone.utc).isoformat()}",
                "",
                "## Alert Details",
                f"**Source:** {alert_data.get('source', 'Unknown')}",
                f"**Category:** {alert_data.get('category', 'Unknown')}",
                f"**Confidence:** {alert_data.get('confidence', 'Unknown')}",
                ""
            ]
            
            if 'description' in alert_data:
                description_parts.extend([
                    "## Alert Description",
                    alert_data['description'],
                    ""
                ])
            
            # Add affected assets
            affected_assets = incident_context.get('affected_assets', [])
            if affected_assets:
                description_parts.extend([
                    "## Affected Assets",
                    "\n".join([f"- {asset}" for asset in affected_assets]),
                    ""
                ])
            
            case_description = "\n".join(description_parts)
            
            # Create case tags
            case_tags = [
                self.case_tag_prefix,
                incident_type,
                severity,
                f"incident_{incident_id[:8]}"
            ]
            
            # Add source system tag
            if alert_data.get('source'):
                case_tags.append(f"source_{alert_data['source']}")
            
            # Create custom fields
            custom_fields = {
                'incident_id': incident_id,
                'original_alert_id': alert_data.get('id', ''),
                'incident_type': incident_type,
                'source_system': alert_data.get('source', ''),
                'created_by_automation': True
            }
            
            # Create TheHive case
            thehive_case = TheHiveCase(
                title=case_title,
                description=case_description,
                severity=case_severity,
                tags=case_tags,
                customFields=custom_fields
            )
            
            # Submit case to TheHive
            case_id = await self._create_case(thehive_case)
            
            if case_id:
                # Create initial tasks
                await self._create_incident_tasks(case_id, incident_type, severity)
                
                # Create observables from IOCs
                iocs = incident_context.get('iocs', [])
                if iocs:
                    await self._create_observables_from_iocs(case_id, iocs)
                
                logger.info("TheHive case created successfully",
                           case_id=case_id,
                           incident_id=incident_id,
                           title=case_title)
            
            return case_id
            
        except Exception as e:
            logger.error("Failed to create TheHive case",
                        incident_id=incident_context.get('incident_id', 'unknown'),
                        error=str(e))
            return None
    
    async def _create_case(self, case: TheHiveCase) -> Optional[str]:
        """Create case in TheHive"""
        try:
            case_data = {
                'title': case.title,
                'description': case.description,
                'severity': case.severity.value,
                'tags': case.tags or [],
                'tlp': case.tlp,
                'customFields': case.customFields or {}
            }
            
            url = f"{self.base_url}/api/v1/case"
            
            async with self.session.post(url, json=case_data) as response:
                if response.status == 201:
                    result = await response.json()
                    case_id = result.get('_id')
                    
                    logger.info("Case created in TheHive",
                               case_id=case_id,
                               title=case.title)
                    
                    return case_id
                else:
                    error_text = await response.text()
                    logger.error("Failed to create case in TheHive",
                               status=response.status,
                               error=error_text)
                    return None
                    
        except Exception as e:
            logger.error("Error creating case in TheHive", error=str(e))
            return None
    
    async def _create_incident_tasks(self, case_id: str, incident_type: str, severity: str):
        """Create standard incident response tasks"""
        try:
            # Define standard tasks based on incident type
            standard_tasks = self._get_standard_tasks_for_incident_type(incident_type, severity)
            
            for task_config in standard_tasks:
                task = TheHiveTask(
                    title=task_config['title'],
                    description=task_config.get('description', ''),
                    group=task_config.get('group', 'incident_response'),
                    assignee=task_config.get('assignee') if self.auto_assign_tasks else None
                )
                
                task_id = await self._create_task(case_id, task)
                
                if task_id:
                    logger.debug("Task created",
                               case_id=case_id,
                               task_id=task_id,
                               title=task.title)
                    
        except Exception as e:
            logger.error("Error creating incident tasks",
                        case_id=case_id,
                        error=str(e))
    
    async def _create_task(self, case_id: str, task: TheHiveTask) -> Optional[str]:
        """Create task in TheHive case"""
        try:
            task_data = {
                'title': task.title,
                'description': task.description,
                'status': task.status.value,
                'group': task.group
            }
            
            if task.assignee:
                task_data['assignee'] = task.assignee
            
            url = f"{self.base_url}/api/v1/case/{case_id}/task"
            
            async with self.session.post(url, json=task_data) as response:
                if response.status == 201:
                    result = await response.json()
                    return result.get('_id')
                else:
                    error_text = await response.text()
                    logger.error("Failed to create task",
                               case_id=case_id,
                               status=response.status,
                               error=error_text)
                    return None
                    
        except Exception as e:
            logger.error("Error creating task", case_id=case_id, error=str(e))
            return None
    
    async def _create_observables_from_iocs(self, case_id: str, iocs: List[Dict[str, Any]]):
        """Create TheHive observables from IOCs"""
        try:
            for ioc in iocs:
                # Map IOC type to TheHive observable type
                observable_type = self._map_ioc_to_observable_type(ioc.get('type', 'other'))
                
                observable = TheHiveObservable(
                    dataType=observable_type,
                    data=str(ioc.get('value', '')),
                    message=f"IOC from incident: {ioc.get('source', 'automated')}",
                    tags=[f"confidence_{ioc.get('confidence', 0)}", "automated"],
                    ioc=True,
                    sighted=False
                )
                
                observable_id = await self._create_observable(case_id, observable)
                
                if observable_id:
                    logger.debug("Observable created",
                               case_id=case_id,
                               observable_id=observable_id,
                               type=observable_type.value,
                               value=observable.data)
                    
        except Exception as e:
            logger.error("Error creating observables",
                        case_id=case_id,
                        error=str(e))
    
    async def _create_observable(self, case_id: str, observable: TheHiveObservable) -> Optional[str]:
        """Create observable in TheHive case"""
        try:
            observable_data = {
                'dataType': observable.dataType.value,
                'data': observable.data,
                'message': observable.message,
                'tags': observable.tags or [],
                'ioc': observable.ioc,
                'sighted': observable.sighted
            }
            
            url = f"{self.base_url}/api/v1/case/{case_id}/observable"
            
            async with self.session.post(url, json=observable_data) as response:
                if response.status == 201:
                    result = await response.json()
                    return result.get('_id')
                else:
                    error_text = await response.text()
                    logger.error("Failed to create observable",
                               case_id=case_id,
                               status=response.status,
                               error=error_text)
                    return None
                    
        except Exception as e:
            logger.error("Error creating observable", case_id=case_id, error=str(e))
            return None
    
    def _get_standard_tasks_for_incident_type(self, incident_type: str, severity: str) -> List[Dict[str, Any]]:
        """Get standard tasks for incident type"""
        
        base_tasks = [
            {
                'title': 'Initial Incident Assessment',
                'description': 'Perform initial assessment of the incident scope and impact',
                'group': 'triage',
                'assignee': 'soc_analyst'
            },
            {
                'title': 'Evidence Collection',
                'description': 'Collect and preserve digital evidence related to the incident',
                'group': 'forensics',
                'assignee': 'forensic_analyst'
            },
            {
                'title': 'Incident Documentation',
                'description': 'Document incident timeline, actions taken, and findings',
                'group': 'documentation',
                'assignee': 'soc_analyst'
            }
        ]
        
        # Add incident-type specific tasks
        if incident_type in ['malware_incident', 'ransomware_incident']:
            base_tasks.extend([
                {
                    'title': 'Malware Analysis',
                    'description': 'Analyze malware sample and determine capabilities',
                    'group': 'analysis',
                    'assignee': 'malware_analyst'
                },
                {
                    'title': 'Endpoint Containment',
                    'description': 'Isolate infected endpoints and prevent spread',
                    'group': 'containment',
                    'assignee': 'incident_responder'
                },
                {
                    'title': 'System Recovery',
                    'description': 'Clean and restore affected systems',
                    'group': 'recovery',
                    'assignee': 'system_admin'
                }
            ])
        
        elif incident_type == 'data_breach':
            base_tasks.extend([
                {
                    'title': 'Data Impact Assessment',
                    'description': 'Assess the scope and sensitivity of compromised data',
                    'group': 'assessment',
                    'assignee': 'data_protection_officer'
                },
                {
                    'title': 'Legal Notification',
                    'description': 'Notify legal team and prepare regulatory notifications',
                    'group': 'legal',
                    'assignee': 'legal_counsel'
                },
                {
                    'title': 'Customer Communication',
                    'description': 'Prepare and send customer breach notifications',
                    'group': 'communication',
                    'assignee': 'communications_team'
                }
            ])
        
        elif incident_type == 'phishing_incident':
            base_tasks.extend([
                {
                    'title': 'Email Analysis',
                    'description': 'Analyze phishing email and extract IOCs',
                    'group': 'analysis',
                    'assignee': 'email_analyst'
                },
                {
                    'title': 'User Impact Assessment',
                    'description': 'Determine which users received and interacted with phishing email',
                    'group': 'assessment',
                    'assignee': 'soc_analyst'
                },
                {
                    'title': 'User Education',
                    'description': 'Educate affected users about the phishing attempt',
                    'group': 'education',
                    'assignee': 'security_awareness'
                }
            ])
        
        elif incident_type == 'ddos_attack':
            base_tasks.extend([
                {
                    'title': 'Traffic Analysis',
                    'description': 'Analyze attack traffic patterns and sources',
                    'group': 'analysis',
                    'assignee': 'network_analyst'
                },
                {
                    'title': 'Mitigation Activation',
                    'description': 'Activate DDoS mitigation measures',
                    'group': 'mitigation',
                    'assignee': 'network_engineer'
                },
                {
                    'title': 'Service Recovery',
                    'description': 'Verify service restoration and performance',
                    'group': 'recovery',
                    'assignee': 'network_engineer'
                }
            ])
        
        # Add high-priority tasks for critical incidents
        if severity.lower() == 'critical':
            base_tasks.insert(0, {
                'title': 'Executive Notification',
                'description': 'Notify executive team of critical security incident',
                'group': 'notification',
                'assignee': 'incident_commander'
            })
        
        return base_tasks
    
    def _map_ioc_to_observable_type(self, ioc_type: str) -> ObservableType:
        """Map IOC type to TheHive observable type"""
        
        mapping = {
            'ip_address': ObservableType.IP,
            'domain': ObservableType.DOMAIN,
            'url': ObservableType.URL,
            'file_hash': ObservableType.HASH,
            'email': ObservableType.MAIL,
            'filename': ObservableType.FILENAME,
            'registry': ObservableType.REGISTRY,
            'user_agent': ObservableType.USER_AGENT
        }
        
        return mapping.get(ioc_type, ObservableType.OTHER)
    
    # Case management methods
    async def update_case_status(self, case_id: str, status: CaseStatus, resolution: str = None) -> bool:
        """Update case status in TheHive"""
        try:
            update_data = {'status': status.value}
            
            if resolution and status == CaseStatus.RESOLVED:
                update_data['resolution'] = resolution
            
            url = f"{self.base_url}/api/v1/case/{case_id}"
            
            async with self.session.patch(url, json=update_data) as response:
                if response.status == 200:
                    logger.info("Case status updated",
                               case_id=case_id,
                               status=status.value)
                    return True
                else:
                    error_text = await response.text()
                    logger.error("Failed to update case status",
                               case_id=case_id,
                               status=response.status,
                               error=error_text)
                    return False
                    
        except Exception as e:
            logger.error("Error updating case status", case_id=case_id, error=str(e))
            return False
    
    async def add_case_comment(self, case_id: str, comment: str) -> bool:
        """Add comment to TheHive case"""
        try:
            comment_data = {
                'message': comment,
                'startDate': int(datetime.now(timezone.utc).timestamp() * 1000)
            }
            
            url = f"{self.base_url}/api/v1/case/{case_id}/comment"
            
            async with self.session.post(url, json=comment_data) as response:
                if response.status == 201:
                    logger.debug("Comment added to case", case_id=case_id)
                    return True
                else:
                    error_text = await response.text()
                    logger.error("Failed to add case comment",
                               case_id=case_id,
                               status=response.status,
                               error=error_text)
                    return False
                    
        except Exception as e:
            logger.error("Error adding case comment", case_id=case_id, error=str(e))
            return False
    
    async def update_task_status(self, task_id: str, status: TaskStatus) -> bool:
        """Update task status in TheHive"""
        try:
            update_data = {'status': status.value}
            
            url = f"{self.base_url}/api/v1/task/{task_id}"
            
            async with self.session.patch(url, json=update_data) as response:
                if response.status == 200:
                    logger.debug("Task status updated",
                               task_id=task_id,
                               status=status.value)
                    return True
                else:
                    error_text = await response.text()
                    logger.error("Failed to update task status",
                               task_id=task_id,
                               status=response.status,
                               error=error_text)
                    return False
                    
        except Exception as e:
            logger.error("Error updating task status", task_id=task_id, error=str(e))
            return False
    
    async def get_case_details(self, case_id: str) -> Optional[Dict[str, Any]]:
        """Get case details from TheHive"""
        try:
            url = f"{self.base_url}/api/v1/case/{case_id}"
            
            async with self.session.get(url) as response:
                if response.status == 200:
                    return await response.json()
                else:
                    logger.error("Failed to get case details",
                               case_id=case_id,
                               status=response.status)
                    return None
                    
        except Exception as e:
            logger.error("Error getting case details", case_id=case_id, error=str(e))
            return None
    
    async def search_cases(self, query: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Search cases in TheHive"""
        try:
            url = f"{self.base_url}/api/v1/query"
            
            search_query = {
                'query': [
                    {'_name': 'getCase'},
                    {'_name': 'filter', '_and': [query]}
                ]
            }
            
            async with self.session.post(url, json=search_query) as response:
                if response.status == 200:
                    return await response.json()
                else:
                    logger.error("Failed to search cases",
                               status=response.status)
                    return []
                    
        except Exception as e:
            logger.error("Error searching cases", error=str(e))
            return []