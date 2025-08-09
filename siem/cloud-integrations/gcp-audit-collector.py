#!/usr/bin/env python3
"""
iSECTECH SIEM Google Cloud Platform Audit Log Collector
High-performance GCP security event collection and real-time analysis
"""

import asyncio
import json
import logging
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, asdict
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any
from pathlib import Path
import yaml

# Third-party imports
from google.cloud import logging as cloud_logging
from google.cloud import securitycenter
from google.cloud import asset_v1
from google.cloud import monitoring_v3
from google.oauth2 import service_account
from kafka import KafkaProducer
from prometheus_client import Counter, Histogram, Gauge, start_http_server
import redis
import structlog

# ═══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION AND DATA STRUCTURES
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class GCPProject:
    """GCP project configuration"""
    project_id: str
    project_name: str
    organization_id: str
    service_account_key_path: str
    log_sink_name: str
    security_center_enabled: bool = True
    cloud_asset_enabled: bool = True
    monitoring_enabled: bool = True
    enabled: bool = True
    criticality: str = "medium"
    environment: str = "production"
    tags: List[str] = None

    def __post_init__(self):
        if self.tags is None:
            self.tags = []

@dataclass
class GCPAuditEvent:
    """GCP Audit Log event structure"""
    event_time: datetime
    event_source: str
    event_name: str
    gcp_region: str
    caller_ip: str
    caller_user_agent: str
    principal_email: str
    service_name: str
    method_name: str
    resource_name: str
    resource_type: str
    project_id: str
    operation_id: str
    request_metadata: Dict[str, Any]
    request: Dict[str, Any]
    response: Dict[str, Any]
    status: Dict[str, Any]
    authorization_info: List[Dict[str, Any]]
    
    # Enhanced security fields
    risk_score: int = 1
    security_relevant: bool = False
    threat_indicators: List[str] = None
    compliance_violations: List[str] = None
    investigation_priority: str = "low"
    
    def __post_init__(self):
        if self.threat_indicators is None:
            self.threat_indicators = []
        if self.compliance_violations is None:
            self.compliance_violations = []

class GCPCollectorConfig:
    """Configuration management for GCP collector"""
    
    def __init__(self, config_file: str = "/etc/isectech-siem/gcp-collector.yaml"):
        self.config_file = Path(config_file)
        self.config = self._load_config()
        
    def _load_config(self) -> Dict:
        """Load configuration from YAML file"""
        try:
            with open(self.config_file, 'r') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            return self._default_config()
    
    def _default_config(self) -> Dict:
        """Default configuration"""
        return {
            "collector": {
                "worker_threads": 10,
                "batch_size": 100,
                "collection_interval": 300,  # 5 minutes
                "retry_interval": 60,
                "metrics_port": 9166
            },
            "kafka": {
                "bootstrap_servers": ["kafka-1.isectech.local:9092"],
                "topic": "gcp-security-events",
                "batch_size": 1000,
                "linger_ms": 1000,
                "compression_type": "gzip"
            },
            "redis": {
                "host": "redis.isectech.local",
                "port": 6379,
                "db": 6,
                "password": None
            },
            "security": {
                "high_risk_methods": [
                    "google.iam.admin.v1.IAM.CreateRole",
                    "google.iam.admin.v1.IAM.DeleteRole",
                    "google.iam.admin.v1.IAM.SetIamPolicy",
                    "google.compute.v1.Instances.Delete",
                    "google.compute.v1.Instances.Stop",
                    "google.storage.v1.Storage.Objects.Delete",
                    "google.storage.v1.Storage.Buckets.Delete",
                    "google.cloud.sql.v1beta4.SqlInstancesService.Delete",
                    "google.container.v1.ClusterManager.DeleteCluster",
                    "google.logging.v2.ConfigServiceV2.DeleteLogMetric",
                    "google.logging.v2.ConfigServiceV2.DeleteSink"
                ],
                "critical_services": [
                    "iam.googleapis.com",
                    "cloudkms.googleapis.com",
                    "logging.googleapis.com",
                    "monitoring.googleapis.com",
                    "securitycenter.googleapis.com",
                    "compute.googleapis.com",
                    "storage.googleapis.com",
                    "container.googleapis.com"
                ],
                "authentication_methods": [
                    "google.iam.admin.v1.IAM.CreateServiceAccount",
                    "google.iam.admin.v1.IAM.CreateServiceAccountKey",
                    "google.iam.admin.v1.IAM.DeleteServiceAccount",
                    "google.iam.admin.v1.IAM.SetIamPolicy"
                ]
            },
            "logging": {
                "level": "INFO",
                "format": "json"
            }
        }

# ═══════════════════════════════════════════════════════════════════════════════
# SECURITY ANALYSIS RULES
# ═══════════════════════════════════════════════════════════════════════════════

# High-risk GCP methods with base risk scores
HIGH_RISK_METHODS = {
    # IAM and Security
    "google.iam.admin.v1.IAM.CreateRole": 7,
    "google.iam.admin.v1.IAM.DeleteRole": 8,
    "google.iam.admin.v1.IAM.SetIamPolicy": 6,
    "google.iam.admin.v1.IAM.CreateServiceAccount": 5,
    "google.iam.admin.v1.IAM.DeleteServiceAccount": 7,
    "google.iam.admin.v1.IAM.CreateServiceAccountKey": 6,
    "google.iam.admin.v1.IAM.DeleteServiceAccountKey": 5,
    
    # Compute Engine
    "google.compute.v1.Instances.Delete": 6,
    "google.compute.v1.Instances.Stop": 4,
    "google.compute.v1.Instances.Reset": 4,
    "google.compute.v1.Disks.Delete": 5,
    "google.compute.v1.Snapshots.Delete": 4,
    "google.compute.v1.Firewalls.Insert": 5,
    "google.compute.v1.Firewalls.Delete": 6,
    "google.compute.v1.Firewalls.Update": 4,
    
    # Storage
    "google.storage.v1.Storage.Buckets.Delete": 7,
    "google.storage.v1.Storage.Objects.Delete": 4,
    "google.storage.v1.Storage.BucketAccessControls.Update": 5,
    "google.storage.v1.Storage.DefaultObjectAccessControls.Update": 5,
    
    # Cloud SQL
    "google.cloud.sql.v1beta4.SqlInstancesService.Delete": 8,
    "google.cloud.sql.v1beta4.SqlInstancesService.Patch": 4,
    "google.cloud.sql.v1beta4.SqlUsersService.Delete": 5,
    
    # Kubernetes Engine
    "google.container.v1.ClusterManager.DeleteCluster": 8,
    "google.container.v1.ClusterManager.UpdateCluster": 4,
    "google.container.v1.ClusterManager.CreateCluster": 4,
    
    # Cloud KMS
    "google.cloud.kms.v1.KeyManagementService.DestroyCryptoKeyVersion": 9,
    "google.cloud.kms.v1.KeyManagementService.UpdateCryptoKey": 6,
    "google.cloud.kms.v1.KeyManagementService.SetIamPolicy": 7,
    
    # Logging and Monitoring
    "google.logging.v2.ConfigServiceV2.DeleteLogMetric": 7,
    "google.logging.v2.ConfigServiceV2.DeleteSink": 8,
    "google.monitoring.v3.MetricService.DeleteMetricDescriptor": 6,
    "google.monitoring.v3.AlertPolicyService.DeleteAlertPolicy": 6,
    
    # Security Center
    "google.cloud.securitycenter.v1.SecurityCenter.SetIamPolicy": 7,
    "google.cloud.securitycenter.v1.SecurityCenter.UpdateSecurityMarks": 5,
    
    # Resource Manager
    "google.cloud.resourcemanager.v1.Projects.Delete": 9,
    "google.cloud.resourcemanager.v1.Organizations.SetIamPolicy": 8,
    "google.cloud.resourcemanager.v1.Folders.SetIamPolicy": 7
}

# Status codes that indicate security issues
SECURITY_STATUS_CODES = [
    "PERMISSION_DENIED",
    "UNAUTHENTICATED",
    "INVALID_ARGUMENT",
    "FAILED_PRECONDITION"
]

# ═══════════════════════════════════════════════════════════════════════════════
# METRICS AND MONITORING
# ═══════════════════════════════════════════════════════════════════════════════

# Prometheus metrics
gcp_events_total = Counter('gcp_events_total', 'Total GCP events processed', ['project', 'service', 'method'])
gcp_security_alerts_total = Counter('gcp_security_alerts_total', 'Security alerts from GCP events', ['project', 'alert_type'])
gcp_collection_duration = Histogram('gcp_collection_duration_seconds', 'GCP collection duration', ['project', 'service'])
gcp_api_errors_total = Counter('gcp_api_errors_total', 'GCP API errors', ['project', 'service', 'error_type'])
active_projects = Gauge('gcp_active_projects', 'Number of active GCP projects being monitored')

# ═══════════════════════════════════════════════════════════════════════════════
# GCP COLLECTOR CLASS
# ═══════════════════════════════════════════════════════════════════════════════

class GCPAuditCollector:
    """High-performance GCP Audit Log and security event collector"""
    
    def __init__(self, config_file: str = "/etc/isectech-siem/gcp-collector.yaml"):
        self.config = GCPCollectorConfig(config_file)
        self.logger = self._setup_logging()
        self.projects: Dict[str, GCPProject] = {}
        self.running = False
        self.tasks = []
        
        # Initialize components
        self.kafka_producer = None
        self.redis_client = None
        self.executor = ThreadPoolExecutor(max_workers=self.config.config["collector"]["worker_threads"])
        
    def _setup_logging(self) -> structlog.BoundLogger:
        """Setup structured logging"""
        logging.basicConfig(
            level=getattr(logging, self.config.config["logging"]["level"]),
            format="%(message)s"
        )
        
        structlog.configure(
            processors=[
                structlog.stdlib.filter_by_level,
                structlog.stdlib.add_logger_name,
                structlog.stdlib.add_log_level,
                structlog.stdlib.PositionalArgumentsFormatter(),
                structlog.processors.TimeStamper(fmt="iso"),
                structlog.processors.StackInfoRenderer(),
                structlog.processors.format_exc_info,
                structlog.processors.UnicodeDecoder(),
                structlog.processors.JSONRenderer()
            ],
            context_class=dict,
            logger_factory=structlog.stdlib.LoggerFactory(),
            wrapper_class=structlog.stdlib.BoundLogger,
            cache_logger_on_first_use=True,
        )
        
        return structlog.get_logger("gcp_collector")
    
    async def initialize(self):
        """Initialize collector components"""
        self.logger.info("Initializing GCP Audit collector")
        
        # Initialize Kafka producer
        self.kafka_producer = KafkaProducer(
            bootstrap_servers=self.config.config["kafka"]["bootstrap_servers"],
            value_serializer=lambda v: json.dumps(v).encode('utf-8'),
            batch_size=self.config.config["kafka"]["batch_size"],
            linger_ms=self.config.config["kafka"]["linger_ms"],
            compression_type=self.config.config["kafka"]["compression_type"]
        )
        
        # Initialize Redis client
        redis_config = self.config.config["redis"]
        self.redis_client = redis.Redis(
            host=redis_config["host"],
            port=redis_config["port"],
            db=redis_config["db"],
            password=redis_config.get("password"),
            decode_responses=True
        )
        
        # Load GCP project configurations
        await self._load_projects()
        
        # Start Prometheus metrics server
        start_http_server(self.config.config["collector"]["metrics_port"])
        
        self.logger.info("GCP collector initialized", projects_count=len(self.projects))
    
    async def _load_projects(self):
        """Load GCP project configurations"""
        # In production, this would load from a secure configuration store
        sample_projects = [
            GCPProject(
                project_id="isectech-prod-main",
                project_name="Production Main",
                organization_id="123456789012",
                service_account_key_path="/etc/isectech-siem/gcp-keys/prod-main-sa-key.json",
                log_sink_name="siem-audit-logs",
                criticality="critical",
                environment="production",
                tags=["production", "critical", "main"]
            ),
            GCPProject(
                project_id="isectech-dev-sandbox",
                project_name="Development Sandbox",
                organization_id="123456789012",
                service_account_key_path="/etc/isectech-siem/gcp-keys/dev-sandbox-sa-key.json",
                log_sink_name="siem-audit-logs",
                criticality="medium",
                environment="development",
                tags=["development", "non-production", "sandbox"]
            )
        ]
        
        for project in sample_projects:
            self.projects[project.project_id] = project
    
    async def start(self):
        """Start the GCP collector"""
        self.logger.info("Starting GCP Audit collector")
        self.running = True
        
        # Schedule collection tasks for each project
        for project_id, project in self.projects.items():
            if project.enabled:
                task = asyncio.create_task(self._project_collection_loop(project))
                self.tasks.append(task)
        
        # Start monitoring task
        self.tasks.append(asyncio.create_task(self._monitoring_loop()))
        
        # Wait for all tasks
        await asyncio.gather(*self.tasks, return_exceptions=True)
    
    async def stop(self):
        """Stop the GCP collector"""
        self.logger.info("Stopping GCP Audit collector")
        self.running = False
        
        # Cancel all tasks
        for task in self.tasks:
            task.cancel()
        
        # Wait for tasks to complete
        await asyncio.gather(*self.tasks, return_exceptions=True)
        
        # Close connections
        if self.kafka_producer:
            self.kafka_producer.close()
        if self.redis_client:
            self.redis_client.close()
        
        self.executor.shutdown(wait=True)
    
    async def _project_collection_loop(self, project: GCPProject):
        """Main collection loop for a GCP project"""
        logger = self.logger.bind(project=project.project_name)
        
        while self.running:
            try:
                start_time = time.time()
                
                # Collect Audit Log events
                events = await self._collect_audit_log_events(project)
                
                # Collect Security Center findings
                if project.security_center_enabled:
                    security_findings = await self._collect_security_center_findings(project)
                    events.extend(security_findings)
                
                # Collect Cloud Asset inventory changes
                if project.cloud_asset_enabled:
                    asset_events = await self._collect_asset_inventory_events(project)
                    events.extend(asset_events)
                
                # Process and send results
                await self._process_events(events, project)
                
                collection_duration = time.time() - start_time
                gcp_collection_duration.labels(project=project.project_name, service="audit_log").observe(collection_duration)
                
                logger.debug("Collection completed", 
                           events_collected=len(events),
                           duration=collection_duration)
                
            except Exception as e:
                gcp_api_errors_total.labels(project=project.project_name, service="audit_log", error_type=type(e).__name__).inc()
                logger.error("Collection failed", error=str(e))
            
            # Wait for next collection interval
            await asyncio.sleep(self.config.config["collector"]["collection_interval"])
    
    async def _collect_audit_log_events(self, project: GCPProject) -> List[GCPAuditEvent]:
        """Collect GCP Audit Log events"""
        events = []
        
        try:
            # Create credentials
            credentials = service_account.Credentials.from_service_account_file(
                project.service_account_key_path
            )
            
            # Create logging client
            logging_client = cloud_logging.Client(project=project.project_id, credentials=credentials)
            
            # Get last processed timestamp from Redis
            last_processed_key = f"gcp:audit_log:{project.project_id}:last_processed"
            last_processed = self.redis_client.get(last_processed_key)
            if last_processed:
                last_processed = datetime.fromisoformat(last_processed)
            else:
                # Start from 1 hour ago if no previous state
                last_processed = datetime.now(timezone.utc) - timedelta(hours=1)
            
            # Set end time to current time
            end_time = datetime.now(timezone.utc)
            
            # Build filter for audit logs
            filter_expression = f'''
                logName=~"projects/{project.project_id}/logs/cloudaudit.googleapis.com"
                AND timestamp >= "{last_processed.isoformat()}"
                AND timestamp <= "{end_time.isoformat()}"
                AND protoPayload.serviceName != ""
                AND protoPayload.methodName != ""
            '''.strip().replace('\n', ' ')
            
            # List log entries
            entries = logging_client.list_entries(filter_=filter_expression, max_results=1000)
            
            for entry in entries:
                event = self._parse_audit_log_entry(entry, project)
                if event:
                    events.append(event)
            
            # Update last processed timestamp
            self.redis_client.set(last_processed_key, end_time.isoformat())
            
        except Exception as e:
            self.logger.error("Failed to collect Audit Log events", project=project.project_name, error=str(e))
        
        return events
    
    def _parse_audit_log_entry(self, entry: Any, project: GCPProject) -> Optional[GCPAuditEvent]:
        """Parse an Audit Log entry into our event structure"""
        try:
            payload = entry.payload
            if not hasattr(payload, 'service_name') or not hasattr(payload, 'method_name'):
                return None
            
            # Extract timestamp
            event_time = entry.timestamp
            if not isinstance(event_time, datetime):
                event_time = datetime.fromisoformat(str(event_time).replace('Z', '+00:00'))
            
            # Extract request metadata
            request_metadata = {}
            if hasattr(payload, 'request_metadata'):
                request_metadata = {
                    'caller_ip': getattr(payload.request_metadata, 'caller_ip', ''),
                    'caller_supplied_user_agent': getattr(payload.request_metadata, 'caller_supplied_user_agent', ''),
                    'caller_network': getattr(payload.request_metadata, 'caller_network', ''),
                    'request_attributes': getattr(payload.request_metadata, 'request_attributes', {})
                }
            
            event = GCPAuditEvent(
                event_time=event_time,
                event_source="cloudaudit.googleapis.com",
                event_name=payload.method_name,
                gcp_region=getattr(entry, 'location', ''),
                caller_ip=request_metadata.get('caller_ip', ''),
                caller_user_agent=request_metadata.get('caller_supplied_user_agent', ''),
                principal_email=getattr(payload.authentication_info, 'principal_email', '') if hasattr(payload, 'authentication_info') else '',
                service_name=payload.service_name,
                method_name=payload.method_name,
                resource_name=getattr(payload, 'resource_name', ''),
                resource_type=getattr(payload, 'resource_type', ''),
                project_id=project.project_id,
                operation_id=getattr(payload, 'operation_id', ''),
                request_metadata=request_metadata,
                request=self._proto_to_dict(getattr(payload, 'request', {})),
                response=self._proto_to_dict(getattr(payload, 'response', {})),
                status=self._proto_to_dict(getattr(payload, 'status', {})),
                authorization_info=[self._proto_to_dict(auth) for auth in getattr(payload, 'authorization_info', [])]
            )
            
            # Perform security analysis
            self._analyze_event_security(event, project)
            
            return event
            
        except Exception as e:
            self.logger.error("Failed to parse Audit Log entry", error=str(e))
            return None
    
    def _proto_to_dict(self, proto_obj: Any) -> Dict[str, Any]:
        """Convert protobuf object to dictionary"""
        try:
            if hasattr(proto_obj, '__dict__'):
                return {k: v for k, v in proto_obj.__dict__.items() if not k.startswith('_')}
            else:
                return {}
        except:
            return {}
    
    def _analyze_event_security(self, event: GCPAuditEvent, project: GCPProject):
        """Perform security analysis on the event"""
        # Base risk score from method type
        event.risk_score = HIGH_RISK_METHODS.get(event.method_name, 1)
        
        # Mark as security relevant if it's a high-risk method
        if event.method_name in HIGH_RISK_METHODS:
            event.security_relevant = True
        
        # Check for critical services
        if event.service_name in self.config.config["security"]["critical_services"]:
            event.risk_score += 1
            event.security_relevant = True
        
        # Analyze status for errors
        if event.status:
            status_code = event.status.get('code', 0)
            if status_code != 0:  # Non-zero status indicates error
                status_message = event.status.get('message', '')
                if any(sec_status in status_message for sec_status in SECURITY_STATUS_CODES):
                    event.risk_score += 3
                    event.threat_indicators.append(f"access_denied_{status_code}")
                else:
                    event.risk_score += 1
                    event.threat_indicators.append("operation_failure")
        
        # Analyze caller patterns
        if event.principal_email:
            # Check for service account usage in high-risk operations
            if "@" in event.principal_email and event.principal_email.endswith(".iam.gserviceaccount.com"):
                if event.risk_score >= 6:
                    event.risk_score += 1
                    event.threat_indicators.append("service_account_privileged_operation")
            
            # Check for external accounts
            if not event.principal_email.endswith(f"@{project.project_id}.iam.gserviceaccount.com") and \
               not event.principal_email.endswith("@isectech.com"):  # Adjust for your domain
                event.risk_score += 2
                event.threat_indicators.append("external_account_access")
        
        # Analyze IP address patterns
        if event.caller_ip:
            if self._is_suspicious_ip(event.caller_ip):
                event.risk_score += 3
                event.threat_indicators.append("suspicious_source_ip")
        
        # Check for privilege escalation
        if self._is_privilege_escalation(event):
            event.risk_score += 4
            event.threat_indicators.append("privilege_escalation")
        
        # Check for resource deletion patterns
        if "Delete" in event.method_name or "Destroy" in event.method_name:
            event.risk_score += 2
            event.threat_indicators.append("resource_deletion")
        
        # Analyze time-based patterns
        if self._is_off_hours_activity(event.event_time):
            event.risk_score += 1
            event.threat_indicators.append("off_hours_activity")
        
        # Check for compliance violations
        if self._is_compliance_violation(event):
            event.compliance_violations.append("security_configuration_change")
            event.risk_score += 2
        
        # Check for authentication-related events
        if event.method_name in self.config.config["security"]["authentication_methods"]:
            event.security_relevant = True
            if "Delete" in event.method_name:
                event.risk_score += 2
                event.threat_indicators.append("authentication_modification")
        
        # Set investigation priority
        if event.risk_score >= 8:
            event.investigation_priority = "critical"
        elif event.risk_score >= 6:
            event.investigation_priority = "high"
        elif event.risk_score >= 4:
            event.investigation_priority = "medium"
        else:
            event.investigation_priority = "low"
        
        # Cap risk score at 10
        event.risk_score = min(event.risk_score, 10)
    
    def _is_suspicious_ip(self, ip_address: str) -> bool:
        """Check if IP address is suspicious"""
        # In production, this would check against threat intelligence feeds
        # For now, check for common patterns
        if ip_address in ["0.0.0.0", "127.0.0.1", "::1"]:
            return True
        
        # Check for tor exit nodes or known malicious IPs (stub)
        return False
    
    def _is_privilege_escalation(self, event: GCPAuditEvent) -> bool:
        """Detect privilege escalation patterns"""
        escalation_methods = [
            "google.iam.admin.v1.IAM.SetIamPolicy",
            "google.iam.admin.v1.IAM.CreateRole",
            "google.cloud.resourcemanager.v1.Organizations.SetIamPolicy",
            "google.cloud.resourcemanager.v1.Projects.SetIamPolicy"
        ]
        
        if event.method_name in escalation_methods:
            # Check if granting high-privilege roles
            request = event.request
            if isinstance(request, dict) and 'policy' in request:
                policy = request['policy']
                if isinstance(policy, dict) and 'bindings' in policy:
                    for binding in policy['bindings']:
                        role = binding.get('role', '')
                        if any(privilege in role for privilege in ["owner", "editor", "admin", "security"]):
                            return True
        
        return False
    
    def _is_off_hours_activity(self, event_time: datetime) -> bool:
        """Check if activity occurred during off hours"""
        # Business hours: 8 AM to 6 PM Monday-Friday
        hour = event_time.hour
        weekday = event_time.weekday()  # 0=Monday, 6=Sunday
        
        return hour < 8 or hour > 18 or weekday >= 5
    
    def _is_compliance_violation(self, event: GCPAuditEvent) -> bool:
        """Check for compliance violations"""
        # Example: Disabling logging
        if "google.logging.v2.ConfigServiceV2.Delete" in event.method_name:
            return True
        
        # Example: Modifying KMS keys
        if "google.cloud.kms.v1.KeyManagementService" in event.method_name and "Destroy" in event.method_name:
            return True
        
        # Example: Changing security policies
        if "SecurityCenter" in event.service_name and any(action in event.method_name for action in ["Delete", "Update"]):
            return True
        
        return False
    
    async def _collect_security_center_findings(self, project: GCPProject) -> List[GCPAuditEvent]:
        """Collect GCP Security Center findings"""
        findings = []
        
        try:
            credentials = service_account.Credentials.from_service_account_file(
                project.service_account_key_path
            )
            
            security_client = securitycenter.SecurityCenterClient(credentials=credentials)
            
            # Get findings from the last collection interval
            org_name = f"organizations/{project.organization_id}"
            
            # List findings
            request = securitycenter.ListFindingsRequest(
                parent=f"{org_name}/sources/-",
                filter=f'resource.project_number="{project.project_id}" AND state="ACTIVE"'
            )
            
            page_result = security_client.list_findings(request=request)
            
            for response in page_result:
                event = self._parse_security_center_finding(response.finding, project)
                if event:
                    findings.append(event)
        
        except Exception as e:
            self.logger.error("Failed to collect Security Center findings", project=project.project_name, error=str(e))
        
        return findings
    
    def _parse_security_center_finding(self, finding: Any, project: GCPProject) -> Optional[GCPAuditEvent]:
        """Parse Security Center finding into Audit Log event format"""
        try:
            event = GCPAuditEvent(
                event_time=finding.event_time,
                event_source="securitycenter.googleapis.com",
                event_name=f"SecurityFinding_{finding.category}",
                gcp_region=getattr(finding.resource, 'region', ''),
                caller_ip="",
                caller_user_agent="SecurityCenter",
                principal_email="",
                service_name="securitycenter.googleapis.com",
                method_name=f"google.cloud.securitycenter.v1.SecurityCenter.{finding.category}",
                resource_name=finding.resource.name,
                resource_type=finding.resource.type,
                project_id=project.project_id,
                operation_id=finding.name,
                request_metadata={},
                request={},
                response={},
                status={},
                authorization_info=[],
                risk_score=self._map_severity_to_risk_score(finding.severity),
                security_relevant=True,
                threat_indicators=[finding.category],
                investigation_priority="high" if finding.severity in ["HIGH", "CRITICAL"] else "medium"
            )
            
            return event
            
        except Exception as e:
            self.logger.error("Failed to parse Security Center finding", error=str(e))
            return None
    
    def _map_severity_to_risk_score(self, severity: str) -> int:
        """Map Security Center severity to risk score"""
        severity_mapping = {
            "CRITICAL": 9,
            "HIGH": 7,
            "MEDIUM": 5,
            "LOW": 3
        }
        return severity_mapping.get(severity, 3)
    
    async def _collect_asset_inventory_events(self, project: GCPProject) -> List[GCPAuditEvent]:
        """Collect Cloud Asset inventory change events"""
        events = []
        
        try:
            credentials = service_account.Credentials.from_service_account_file(
                project.service_account_key_path
            )
            
            asset_client = asset_v1.AssetServiceClient(credentials=credentials)
            
            # Get asset history for the last collection interval
            parent = f"projects/{project.project_id}"
            
            # Get last processed timestamp
            last_processed_key = f"gcp:asset_inventory:{project.project_id}:last_processed"
            last_processed = self.redis_client.get(last_processed_key)
            if last_processed:
                last_processed_dt = datetime.fromisoformat(last_processed)
            else:
                last_processed_dt = datetime.now(timezone.utc) - timedelta(hours=1)
            
            current_time = datetime.now(timezone.utc)
            
            # List assets with history
            request = asset_v1.BatchGetAssetsHistoryRequest(
                parent=parent,
                asset_names=[],  # Empty to get all assets
                content_type=asset_v1.ContentType.RESOURCE,
                read_time_window=asset_v1.TimeWindow(
                    start_time=last_processed_dt,
                    end_time=current_time
                )
            )
            
            # This is a simplified version - in production you'd need to handle pagination
            # and filter for specific asset types of interest
            
            # Update last processed timestamp
            self.redis_client.set(last_processed_key, current_time.isoformat())
        
        except Exception as e:
            self.logger.error("Failed to collect asset inventory events", project=project.project_name, error=str(e))
        
        return events
    
    async def _process_events(self, events: List[GCPAuditEvent], project: GCPProject):
        """Process and send GCP events"""
        for event in events:
            # Update metrics
            service = event.service_name.split('.')[0] if '.' in event.service_name else event.service_name
            gcp_events_total.labels(project=project.project_name, service=service, method=event.method_name).inc()
            
            # Check for security alerts
            if event.security_relevant or event.risk_score >= 6:
                await self._create_security_alert(event, project)
            
            # Cache event for correlation
            await self._cache_event(event, project)
            
            # Send to Kafka
            await self._send_to_kafka(event, project)
    
    async def _create_security_alert(self, event: GCPAuditEvent, project: GCPProject):
        """Create security alert for high-risk events"""
        alert_types = []
        
        if event.threat_indicators:
            alert_types.extend(event.threat_indicators)
        if event.compliance_violations:
            alert_types.extend(event.compliance_violations)
        if event.risk_score >= 8:
            alert_types.append("high_risk_activity")
        
        for alert_type in alert_types:
            gcp_security_alerts_total.labels(project=project.project_name, alert_type=alert_type).inc()
        
        # Create alert payload
        alert = {
            "alert_id": f"gcp_{project.project_id}_{event.operation_id}",
            "timestamp": event.event_time.isoformat(),
            "project_id": project.project_id,
            "project_name": project.project_name,
            "environment": project.environment,
            "method_name": event.method_name,
            "service_name": event.service_name,
            "principal_email": event.principal_email,
            "caller_ip": event.caller_ip,
            "risk_score": event.risk_score,
            "investigation_priority": event.investigation_priority,
            "threat_indicators": event.threat_indicators,
            "compliance_violations": event.compliance_violations,
            "gcp_region": event.gcp_region,
            "raw_event": asdict(event)
        }
        
        # Send to high-priority topic
        self.kafka_producer.send("gcp-security-alerts", alert)
        
        self.logger.warning("GCP security alert created",
                          project=project.project_name,
                          method_name=event.method_name,
                          risk_score=event.risk_score,
                          alert_types=alert_types)
    
    async def _cache_event(self, event: GCPAuditEvent, project: GCPProject):
        """Cache event for correlation analysis"""
        try:
            cache_key = f"gcp:event:{project.project_id}:{event.operation_id}"
            cache_data = {
                "method_name": event.method_name,
                "service_name": event.service_name,
                "principal_email": event.principal_email,
                "caller_ip": event.caller_ip,
                "timestamp": event.event_time.isoformat(),
                "risk_score": event.risk_score,
                "security_relevant": event.security_relevant
            }
            
            # Store with TTL of 24 hours
            self.redis_client.setex(cache_key, 86400, json.dumps(cache_data))
            
        except Exception as e:
            self.logger.error("Failed to cache event", error=str(e))
    
    async def _send_to_kafka(self, event: GCPAuditEvent, project: GCPProject):
        """Send event to Kafka"""
        try:
            # Convert event to dict for JSON serialization
            message = asdict(event)
            message["timestamp"] = event.event_time.isoformat()
            message["project_name"] = project.project_name
            message["environment"] = project.environment
            message["tenant_id"] = "isectech"
            
            # Send to Kafka
            self.kafka_producer.send(
                self.config.config["kafka"]["topic"],
                value=message,
                key=f"{project.project_id}:{event.operation_id}"
            )
            
        except Exception as e:
            self.logger.error("Failed to send to Kafka", error=str(e))
    
    async def _monitoring_loop(self):
        """Monitoring and health check loop"""
        while self.running:
            try:
                # Update active projects metric
                active_count = sum(1 for project in self.projects.values() if project.enabled)
                active_projects.set(active_count)
                
                # Perform health checks
                await self._health_check()
                
                self.logger.info("Health check completed", active_projects=active_count)
                
            except Exception as e:
                self.logger.error("Monitoring loop error", error=str(e))
            
            await asyncio.sleep(60)  # Health check every minute
    
    async def _health_check(self):
        """Perform health checks on collector components"""
        # Check Kafka connectivity
        try:
            self.kafka_producer.bootstrap_connected()
        except Exception as e:
            self.logger.error("Kafka health check failed", error=str(e))
        
        # Check Redis connectivity
        try:
            self.redis_client.ping()
        except Exception as e:
            self.logger.error("Redis health check failed", error=str(e))
        
        # Check GCP API connectivity for each project
        for project in self.projects.values():
            if project.enabled:
                try:
                    credentials = service_account.Credentials.from_service_account_file(
                        project.service_account_key_path
                    )
                    
                    # Test with Cloud Logging client
                    logging_client = cloud_logging.Client(project=project.project_id, credentials=credentials)
                    # Simple API call to verify connectivity
                    list(logging_client.list_entries(max_results=1))
                    
                except Exception as e:
                    self.logger.error("GCP API health check failed", project=project.project_name, error=str(e))

# ═══════════════════════════════════════════════════════════════════════════════
# MAIN EXECUTION
# ═══════════════════════════════════════════════════════════════════════════════

async def main():
    """Main execution function"""
    collector = GCPAuditCollector()
    
    # Setup signal handling for graceful shutdown
    def signal_handler(signum, frame):
        print(f"\nReceived signal {signum}, shutting down...")
        asyncio.create_task(collector.stop())
    
    import signal
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        await collector.initialize()
        await collector.start()
    except KeyboardInterrupt:
        print("Interrupted by user")
    except Exception as e:
        print(f"Collector error: {e}")
    finally:
        await collector.stop()

if __name__ == "__main__":
    asyncio.run(main())