#!/usr/bin/env python3
"""
iSECTECH SIEM Azure Activity Log Collector
High-performance Azure security event collection and real-time analysis
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
from azure.identity import ClientSecretCredential
from azure.mgmt.monitor import MonitorManagementClient
from azure.mgmt.security import SecurityCenter
from azure.mgmt.resource import ResourceManagementClient
from azure.storage.blob import BlobServiceClient
from kafka import KafkaProducer
from prometheus_client import Counter, Histogram, Gauge, start_http_server
import redis
import structlog
import requests

# ═══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION AND DATA STRUCTURES
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class AzureSubscription:
    """Azure subscription configuration"""
    subscription_id: str
    subscription_name: str
    tenant_id: str
    client_id: str
    client_secret: str
    resource_groups: List[str]
    log_analytics_workspace_id: str
    security_center_enabled: bool = True
    activity_log_storage_account: str = ""
    diagnostic_settings_enabled: bool = True
    enabled: bool = True
    criticality: str = "medium"
    environment: str = "production"
    tags: List[str] = None

    def __post_init__(self):
        if self.tags is None:
            self.tags = []

@dataclass
class AzureActivityEvent:
    """Azure Activity Log event structure"""
    event_time: datetime
    event_source: str
    event_name: str
    azure_region: str
    caller_ip_address: str
    caller: str
    operation_name: str
    operation_id: str
    correlation_id: str
    subscription_id: str
    resource_group_name: str
    resource_provider: str
    resource_type: str
    resource_id: str
    status: str
    sub_status: str
    level: str
    category: str
    authorization: Dict[str, Any]
    claims: Dict[str, Any]
    properties: Dict[str, Any]
    
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

class AzureCollectorConfig:
    """Configuration management for Azure collector"""
    
    def __init__(self, config_file: str = "/etc/isectech-siem/azure-collector.yaml"):
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
                "metrics_port": 9165
            },
            "kafka": {
                "bootstrap_servers": ["kafka-1.isectech.local:9092"],
                "topic": "azure-security-events",
                "batch_size": 1000,
                "linger_ms": 1000,
                "compression_type": "gzip"
            },
            "redis": {
                "host": "redis.isectech.local",
                "port": 6379,
                "db": 5,
                "password": None
            },
            "security": {
                "high_risk_operations": [
                    "Microsoft.Authorization/roleAssignments/write",
                    "Microsoft.Authorization/roleDefinitions/write",
                    "Microsoft.Authorization/policyAssignments/write",
                    "Microsoft.Compute/virtualMachines/delete",
                    "Microsoft.Storage/storageAccounts/delete",
                    "Microsoft.KeyVault/vaults/delete",
                    "Microsoft.Network/networkSecurityGroups/securityRules/write",
                    "Microsoft.Network/networkSecurityGroups/securityRules/delete",
                    "Microsoft.Sql/servers/databases/delete",
                    "Microsoft.Resources/subscriptions/resourceGroups/delete"
                ],
                "critical_resource_types": [
                    "Microsoft.Authorization",
                    "Microsoft.KeyVault",
                    "Microsoft.Security",
                    "Microsoft.Storage",
                    "Microsoft.Sql",
                    "Microsoft.Compute",
                    "Microsoft.Network/networkSecurityGroups"
                ],
                "authentication_operations": [
                    "Sign-in activity",
                    "Microsoft.Authorization/roleAssignments/write",
                    "Microsoft.Authorization/elevateAccess/action"
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

# High-risk Azure operations with base risk scores
HIGH_RISK_OPERATIONS = {
    # Identity and Access Management
    "Microsoft.Authorization/roleAssignments/write": 7,
    "Microsoft.Authorization/roleDefinitions/write": 8,
    "Microsoft.Authorization/policyAssignments/write": 6,
    "Microsoft.Authorization/elevateAccess/action": 9,
    "Microsoft.Authorization/roleAssignments/delete": 6,
    
    # Compute Resources
    "Microsoft.Compute/virtualMachines/delete": 6,
    "Microsoft.Compute/virtualMachines/deallocate/action": 4,
    "Microsoft.Compute/virtualMachines/restart/action": 3,
    "Microsoft.Compute/disks/delete": 5,
    "Microsoft.Compute/snapshots/delete": 4,
    
    # Storage Resources
    "Microsoft.Storage/storageAccounts/delete": 7,
    "Microsoft.Storage/storageAccounts/write": 4,
    "Microsoft.Storage/storageAccounts/listKeys/action": 6,
    "Microsoft.Storage/storageAccounts/regeneratekey/action": 7,
    
    # Key Vault
    "Microsoft.KeyVault/vaults/delete": 8,
    "Microsoft.KeyVault/vaults/keys/delete": 7,
    "Microsoft.KeyVault/vaults/secrets/delete": 6,
    "Microsoft.KeyVault/vaults/accessPolicies/write": 6,
    
    # Network Security
    "Microsoft.Network/networkSecurityGroups/securityRules/write": 6,
    "Microsoft.Network/networkSecurityGroups/securityRules/delete": 5,
    "Microsoft.Network/networkSecurityGroups/delete": 7,
    "Microsoft.Network/virtualNetworks/delete": 6,
    
    # Database
    "Microsoft.Sql/servers/databases/delete": 7,
    "Microsoft.Sql/servers/delete": 8,
    "Microsoft.Sql/servers/firewallRules/write": 5,
    "Microsoft.Sql/servers/firewallRules/delete": 4,
    
    # Resource Management
    "Microsoft.Resources/subscriptions/resourceGroups/delete": 7,
    "Microsoft.Resources/deployments/write": 4,
    
    # Security Center
    "Microsoft.Security/securityContacts/write": 5,
    "Microsoft.Security/securityContacts/delete": 6,
    "Microsoft.Security/policies/write": 6,
    
    # Monitoring and Logging
    "Microsoft.Insights/diagnosticSettings/delete": 7,
    "Microsoft.Insights/activityLogAlerts/delete": 6,
    "Microsoft.OperationalInsights/workspaces/delete": 8
}

# Status codes that indicate security issues
SECURITY_STATUS_CODES = [
    "Forbidden",
    "Unauthorized", 
    "Failed",
    "ClientError"
]

# Suspicious caller patterns
SUSPICIOUS_CALLER_PATTERNS = [
    "unknown",
    "anonymous",
    "service-principal"
]

# ═══════════════════════════════════════════════════════════════════════════════
# METRICS AND MONITORING
# ═══════════════════════════════════════════════════════════════════════════════

# Prometheus metrics
azure_events_total = Counter('azure_events_total', 'Total Azure events processed', ['subscription', 'resource_provider', 'operation'])
azure_security_alerts_total = Counter('azure_security_alerts_total', 'Security alerts from Azure events', ['subscription', 'alert_type'])
azure_collection_duration = Histogram('azure_collection_duration_seconds', 'Azure collection duration', ['subscription', 'service'])
azure_api_errors_total = Counter('azure_api_errors_total', 'Azure API errors', ['subscription', 'service', 'error_type'])
active_subscriptions = Gauge('azure_active_subscriptions', 'Number of active Azure subscriptions being monitored')

# ═══════════════════════════════════════════════════════════════════════════════
# AZURE COLLECTOR CLASS
# ═══════════════════════════════════════════════════════════════════════════════

class AzureActivityCollector:
    """High-performance Azure Activity Log and security event collector"""
    
    def __init__(self, config_file: str = "/etc/isectech-siem/azure-collector.yaml"):
        self.config = AzureCollectorConfig(config_file)
        self.logger = self._setup_logging()
        self.subscriptions: Dict[str, AzureSubscription] = {}
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
        
        return structlog.get_logger("azure_collector")
    
    async def initialize(self):
        """Initialize collector components"""
        self.logger.info("Initializing Azure Activity collector")
        
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
        
        # Load Azure subscription configurations
        await self._load_subscriptions()
        
        # Start Prometheus metrics server
        start_http_server(self.config.config["collector"]["metrics_port"])
        
        self.logger.info("Azure collector initialized", subscriptions_count=len(self.subscriptions))
    
    async def _load_subscriptions(self):
        """Load Azure subscription configurations"""
        # In production, this would load from a secure configuration store
        sample_subscriptions = [
            AzureSubscription(
                subscription_id="12345678-1234-1234-1234-123456789012",
                subscription_name="production-main",
                tenant_id="87654321-4321-4321-4321-210987654321",
                client_id="abcdef12-3456-7890-abcd-ef1234567890",
                client_secret="...",  # Would be from secure store
                resource_groups=["rg-prod-web", "rg-prod-data", "rg-prod-security"],
                log_analytics_workspace_id="/subscriptions/12345678-1234-1234-1234-123456789012/resourceGroups/rg-prod-monitoring/providers/Microsoft.OperationalInsights/workspaces/law-prod-siem",
                criticality="critical",
                environment="production",
                tags=["production", "critical", "main"]
            ),
            AzureSubscription(
                subscription_id="12345678-1234-1234-1234-123456789013",
                subscription_name="development",
                tenant_id="87654321-4321-4321-4321-210987654321",
                client_id="abcdef12-3456-7890-abcd-ef1234567891",
                client_secret="...",
                resource_groups=["rg-dev-web", "rg-dev-data"],
                log_analytics_workspace_id="/subscriptions/12345678-1234-1234-1234-123456789013/resourceGroups/rg-dev-monitoring/providers/Microsoft.OperationalInsights/workspaces/law-dev-siem",
                criticality="medium",
                environment="development",
                tags=["development", "non-production"]
            )
        ]
        
        for subscription in sample_subscriptions:
            self.subscriptions[subscription.subscription_id] = subscription
    
    async def start(self):
        """Start the Azure collector"""
        self.logger.info("Starting Azure Activity collector")
        self.running = True
        
        # Schedule collection tasks for each subscription
        for subscription_id, subscription in self.subscriptions.items():
            if subscription.enabled:
                task = asyncio.create_task(self._subscription_collection_loop(subscription))
                self.tasks.append(task)
        
        # Start monitoring task
        self.tasks.append(asyncio.create_task(self._monitoring_loop()))
        
        # Wait for all tasks
        await asyncio.gather(*self.tasks, return_exceptions=True)
    
    async def stop(self):
        """Stop the Azure collector"""
        self.logger.info("Stopping Azure Activity collector")
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
    
    async def _subscription_collection_loop(self, subscription: AzureSubscription):
        """Main collection loop for an Azure subscription"""
        logger = self.logger.bind(subscription=subscription.subscription_name)
        
        while self.running:
            try:
                start_time = time.time()
                
                # Collect Activity Log events
                events = await self._collect_activity_log_events(subscription)
                
                # Collect Security Center alerts
                if subscription.security_center_enabled:
                    security_alerts = await self._collect_security_center_alerts(subscription)
                    events.extend(security_alerts)
                
                # Collect Azure AD sign-in logs
                signin_events = await self._collect_signin_events(subscription)
                events.extend(signin_events)
                
                # Process and send results
                await self._process_events(events, subscription)
                
                collection_duration = time.time() - start_time
                azure_collection_duration.labels(subscription=subscription.subscription_name, service="activity_log").observe(collection_duration)
                
                logger.debug("Collection completed", 
                           events_collected=len(events),
                           duration=collection_duration)
                
            except Exception as e:
                azure_api_errors_total.labels(subscription=subscription.subscription_name, service="activity_log", error_type=type(e).__name__).inc()
                logger.error("Collection failed", error=str(e))
            
            # Wait for next collection interval
            await asyncio.sleep(self.config.config["collector"]["collection_interval"])
    
    async def _collect_activity_log_events(self, subscription: AzureSubscription) -> List[AzureActivityEvent]:
        """Collect Azure Activity Log events"""
        events = []
        
        try:
            # Create credential
            credential = ClientSecretCredential(
                tenant_id=subscription.tenant_id,
                client_id=subscription.client_id,
                client_secret=subscription.client_secret
            )
            
            # Create Monitor Management client
            monitor_client = MonitorManagementClient(credential, subscription.subscription_id)
            
            # Get last processed timestamp from Redis
            last_processed_key = f"azure:activity_log:{subscription.subscription_id}:last_processed"
            last_processed = self.redis_client.get(last_processed_key)
            if last_processed:
                last_processed = datetime.fromisoformat(last_processed)
            else:
                # Start from 1 hour ago if no previous state
                last_processed = datetime.now(timezone.utc) - timedelta(hours=1)
            
            # Set end time to current time
            end_time = datetime.now(timezone.utc)
            
            # Fetch activity logs
            filter_expression = f"eventTimestamp ge '{last_processed.isoformat()}' and eventTimestamp le '{end_time.isoformat()}'"
            
            activity_logs = monitor_client.activity_logs.list(filter=filter_expression)
            
            for log_entry in activity_logs:
                event = self._parse_activity_log_entry(log_entry, subscription)
                if event:
                    events.append(event)
            
            # Update last processed timestamp
            self.redis_client.set(last_processed_key, end_time.isoformat())
            
        except Exception as e:
            self.logger.error("Failed to collect Activity Log events", subscription=subscription.subscription_name, error=str(e))
        
        return events
    
    def _parse_activity_log_entry(self, log_entry: Any, subscription: AzureSubscription) -> Optional[AzureActivityEvent]:
        """Parse an Activity Log entry into our event structure"""
        try:
            # Extract fields from log entry
            event_time = log_entry.event_timestamp
            if isinstance(event_time, str):
                event_time = datetime.fromisoformat(event_time.replace('Z', '+00:00'))
            
            event = AzureActivityEvent(
                event_time=event_time,
                event_source="Microsoft.Insights/ActivityLogs",
                event_name=log_entry.operation_name.localized_value or log_entry.operation_name.value,
                azure_region=log_entry.resource_group_name or "global",
                caller_ip_address=getattr(log_entry, 'caller', ''),
                caller=getattr(log_entry, 'caller', ''),
                operation_name=log_entry.operation_name.value,
                operation_id=log_entry.operation_id,
                correlation_id=log_entry.correlation_id,
                subscription_id=log_entry.subscription_id,
                resource_group_name=log_entry.resource_group_name or "",
                resource_provider=log_entry.resource_provider_name.value if log_entry.resource_provider_name else "",
                resource_type=log_entry.resource_type.value if log_entry.resource_type else "",
                resource_id=log_entry.resource_id or "",
                status=log_entry.status.value if log_entry.status else "",
                sub_status=log_entry.sub_status.value if log_entry.sub_status else "",
                level=log_entry.level.name if log_entry.level else "",
                category=log_entry.category.value if log_entry.category else "",
                authorization=log_entry.authorization.__dict__ if log_entry.authorization else {},
                claims=getattr(log_entry, 'claims', {}),
                properties=getattr(log_entry, 'properties', {})
            )
            
            # Perform security analysis
            self._analyze_event_security(event, subscription)
            
            return event
            
        except Exception as e:
            self.logger.error("Failed to parse Activity Log entry", error=str(e), operation_id=getattr(log_entry, 'operation_id', 'unknown'))
            return None
    
    def _analyze_event_security(self, event: AzureActivityEvent, subscription: AzureSubscription):
        """Perform security analysis on the event"""
        # Base risk score from operation type
        event.risk_score = HIGH_RISK_OPERATIONS.get(event.operation_name, 1)
        
        # Mark as security relevant if it's a high-risk operation
        if event.operation_name in HIGH_RISK_OPERATIONS:
            event.security_relevant = True
        
        # Check for critical resource types
        resource_provider = event.resource_provider.lower()
        if any(critical in resource_provider for critical in self.config.config["security"]["critical_resource_types"]):
            event.risk_score += 1
            event.security_relevant = True
        
        # Analyze status for failures
        if event.status in SECURITY_STATUS_CODES:
            if event.status in ["Forbidden", "Unauthorized"]:
                event.risk_score += 3
                event.threat_indicators.append(f"access_denied_{event.status.lower()}")
            elif event.status == "Failed":
                event.risk_score += 2
                event.threat_indicators.append("operation_failure")
        
        # Analyze caller patterns
        if event.caller:
            if any(suspicious in event.caller.lower() for suspicious in SUSPICIOUS_CALLER_PATTERNS):
                event.risk_score += 2
                event.threat_indicators.append("suspicious_caller")
            
            # Check for service principal usage in high-risk operations
            if "service-principal" in event.caller.lower() and event.risk_score >= 5:
                event.risk_score += 1
                event.threat_indicators.append("service_principal_privileged_operation")
        
        # Analyze IP address patterns
        if event.caller_ip_address:
            if self._is_suspicious_ip(event.caller_ip_address):
                event.risk_score += 3
                event.threat_indicators.append("suspicious_source_ip")
        
        # Check for privilege escalation
        if self._is_privilege_escalation(event):
            event.risk_score += 4
            event.threat_indicators.append("privilege_escalation")
        
        # Check for resource deletion patterns
        if "delete" in event.operation_name.lower():
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
        # For now, check for common suspicious patterns
        if ip_address in ["0.0.0.0", "127.0.0.1", "::1"]:
            return True
        
        # Check for tor exit nodes or known malicious IPs (stub)
        return False
    
    def _is_privilege_escalation(self, event: AzureActivityEvent) -> bool:
        """Detect privilege escalation patterns"""
        escalation_operations = [
            "Microsoft.Authorization/roleAssignments/write",
            "Microsoft.Authorization/elevateAccess/action",
            "Microsoft.Authorization/roleDefinitions/write"
        ]
        
        if event.operation_name in escalation_operations:
            # Check if assigning high-privilege roles
            authorization = event.authorization
            if isinstance(authorization, dict):
                action = authorization.get('action', '')
                if any(privilege in action for privilege in ["owner", "contributor", "administrator"]):
                    return True
        
        return False
    
    def _is_off_hours_activity(self, event_time: datetime) -> bool:
        """Check if activity occurred during off hours"""
        # Business hours: 8 AM to 6 PM Monday-Friday
        hour = event_time.hour
        weekday = event_time.weekday()  # 0=Monday, 6=Sunday
        
        return hour < 8 or hour > 18 or weekday >= 5
    
    def _is_compliance_violation(self, event: AzureActivityEvent) -> bool:
        """Check for compliance violations"""
        # Example: Disabling diagnostic settings
        if "Microsoft.Insights/diagnosticSettings/delete" in event.operation_name:
            return True
        
        # Example: Modifying security policies
        if "Microsoft.Security" in event.resource_provider and "write" in event.operation_name:
            return True
        
        # Example: Deleting Key Vault resources
        if "Microsoft.KeyVault" in event.resource_provider and "delete" in event.operation_name:
            return True
        
        return False
    
    async def _collect_security_center_alerts(self, subscription: AzureSubscription) -> List[AzureActivityEvent]:
        """Collect Azure Security Center alerts"""
        alerts = []
        
        try:
            credential = ClientSecretCredential(
                tenant_id=subscription.tenant_id,
                client_id=subscription.client_id,
                client_secret=subscription.client_secret
            )
            
            security_client = SecurityCenter(credential, subscription.subscription_id)
            
            # Get alerts from the last collection interval
            security_alerts = security_client.alerts.list()
            
            for alert in security_alerts:
                event = self._parse_security_center_alert(alert, subscription)
                if event:
                    alerts.append(event)
        
        except Exception as e:
            self.logger.error("Failed to collect Security Center alerts", subscription=subscription.subscription_name, error=str(e))
        
        return alerts
    
    def _parse_security_center_alert(self, alert: Any, subscription: AzureSubscription) -> Optional[AzureActivityEvent]:
        """Parse Security Center alert into Activity Log event format"""
        try:
            event = AzureActivityEvent(
                event_time=alert.time_generated_utc,
                event_source="Microsoft.Security/alerts",
                event_name=f"SecurityAlert_{alert.alert_type}",
                azure_region=getattr(alert, 'compromised_entity', ''),
                caller_ip_address="",
                caller="Azure Security Center",
                operation_name=f"Microsoft.Security/alerts/{alert.alert_type}",
                operation_id=alert.system_alert_id,
                correlation_id=alert.correlation_key or "",
                subscription_id=subscription.subscription_id,
                resource_group_name="",
                resource_provider="Microsoft.Security",
                resource_type="alerts",
                resource_id=alert.compromised_entity or "",
                status="Active" if alert.state == "Active" else "Resolved",
                sub_status="",
                level="Warning",
                category="Security",
                authorization={},
                claims={},
                properties={
                    "severity": alert.severity,
                    "description": alert.description,
                    "remediation_steps": alert.remediation_steps,
                    "vendor_name": alert.vendor_name,
                    "alert_type": alert.alert_type
                },
                risk_score=self._map_severity_to_risk_score(alert.severity),
                security_relevant=True,
                threat_indicators=[alert.alert_type],
                investigation_priority="high" if alert.severity in ["High", "Medium"] else "medium"
            )
            
            return event
            
        except Exception as e:
            self.logger.error("Failed to parse Security Center alert", error=str(e))
            return None
    
    def _map_severity_to_risk_score(self, severity: str) -> int:
        """Map Security Center severity to risk score"""
        severity_mapping = {
            "High": 8,
            "Medium": 6,
            "Low": 4,
            "Informational": 2
        }
        return severity_mapping.get(severity, 3)
    
    async def _collect_signin_events(self, subscription: AzureSubscription) -> List[AzureActivityEvent]:
        """Collect Azure AD sign-in events"""
        events = []
        
        try:
            # Use Microsoft Graph API to get sign-in logs
            access_token = await self._get_graph_access_token(subscription)
            
            if not access_token:
                return events
            
            headers = {
                'Authorization': f'Bearer {access_token}',
                'Content-Type': 'application/json'
            }
            
            # Get last processed timestamp
            last_processed_key = f"azure:signin:{subscription.subscription_id}:last_processed"
            last_processed = self.redis_client.get(last_processed_key)
            if last_processed:
                last_processed_dt = datetime.fromisoformat(last_processed)
                filter_param = f"createdDateTime ge {last_processed_dt.isoformat()}"
            else:
                # Start from 1 hour ago
                one_hour_ago = datetime.now(timezone.utc) - timedelta(hours=1)
                filter_param = f"createdDateTime ge {one_hour_ago.isoformat()}"
            
            # Call Microsoft Graph API
            graph_url = f"https://graph.microsoft.com/v1.0/auditLogs/signIns?$filter={filter_param}&$top=1000"
            
            async with self.executor:
                response = requests.get(graph_url, headers=headers)
                
                if response.status_code == 200:
                    signin_data = response.json()
                    
                    for signin in signin_data.get('value', []):
                        event = self._parse_signin_event(signin, subscription)
                        if event:
                            events.append(event)
                    
                    # Update last processed timestamp
                    current_time = datetime.now(timezone.utc)
                    self.redis_client.set(last_processed_key, current_time.isoformat())
        
        except Exception as e:
            self.logger.error("Failed to collect sign-in events", subscription=subscription.subscription_name, error=str(e))
        
        return events
    
    async def _get_graph_access_token(self, subscription: AzureSubscription) -> Optional[str]:
        """Get access token for Microsoft Graph API"""
        try:
            credential = ClientSecretCredential(
                tenant_id=subscription.tenant_id,
                client_id=subscription.client_id,
                client_secret=subscription.client_secret
            )
            
            token = credential.get_token("https://graph.microsoft.com/.default")
            return token.token
        
        except Exception as e:
            self.logger.error("Failed to get Graph access token", error=str(e))
            return None
    
    def _parse_signin_event(self, signin: Dict[str, Any], subscription: AzureSubscription) -> Optional[AzureActivityEvent]:
        """Parse sign-in event into Activity Log event format"""
        try:
            created_time = signin.get('createdDateTime', '')
            if isinstance(created_time, str):
                created_time = datetime.fromisoformat(created_time.replace('Z', '+00:00'))
            
            event = AzureActivityEvent(
                event_time=created_time,
                event_source="Microsoft.AAD/signIns",
                event_name="UserSignIn",
                azure_region="global",
                caller_ip_address=signin.get('ipAddress', ''),
                caller=signin.get('userPrincipalName', ''),
                operation_name="Microsoft.AAD/signIns/write",
                operation_id=signin.get('id', ''),
                correlation_id=signin.get('correlationId', ''),
                subscription_id=subscription.subscription_id,
                resource_group_name="",
                resource_provider="Microsoft.AAD",
                resource_type="signIns",
                resource_id=signin.get('userId', ''),
                status="Success" if signin.get('status', {}).get('errorCode') == 0 else "Failed",
                sub_status=str(signin.get('status', {}).get('errorCode', '')),
                level="Information",
                category="SignIn",
                authorization={},
                claims={},
                properties={
                    "userPrincipalName": signin.get('userPrincipalName', ''),
                    "appDisplayName": signin.get('appDisplayName', ''),
                    "clientAppUsed": signin.get('clientAppUsed', ''),
                    "deviceDetail": signin.get('deviceDetail', {}),
                    "location": signin.get('location', {}),
                    "riskDetail": signin.get('riskDetail', ''),
                    "riskLevelAggregated": signin.get('riskLevelAggregated', ''),
                    "riskState": signin.get('riskState', '')
                }
            )
            
            # Analyze sign-in security
            self._analyze_signin_security(event, signin)
            
            return event
            
        except Exception as e:
            self.logger.error("Failed to parse sign-in event", error=str(e))
            return None
    
    def _analyze_signin_security(self, event: AzureActivityEvent, signin_data: Dict[str, Any]):
        """Analyze sign-in event for security indicators"""
        event.security_relevant = True
        event.risk_score = 1
        
        # Check for failed sign-ins
        if event.status == "Failed":
            event.risk_score += 3
            event.threat_indicators.append("authentication_failure")
        
        # Check for risky sign-ins
        risk_level = signin_data.get('riskLevelAggregated', '')
        if risk_level in ['high', 'medium']:
            event.risk_score += 4 if risk_level == 'high' else 2
            event.threat_indicators.append(f"risky_signin_{risk_level}")
        
        # Check for suspicious locations
        location = signin_data.get('location', {})
        if location.get('countryOrRegion') in ['CN', 'RU', 'KP', 'IR']:
            event.risk_score += 2
            event.threat_indicators.append("suspicious_location")
        
        # Check for legacy authentication
        client_app = signin_data.get('clientAppUsed', '')
        if client_app in ['Exchange ActiveSync', 'Other clients', 'IMAP', 'POP']:
            event.risk_score += 2
            event.threat_indicators.append("legacy_authentication")
        
        # Set priority based on risk
        if event.risk_score >= 6:
            event.investigation_priority = "high"
        elif event.risk_score >= 4:
            event.investigation_priority = "medium"
    
    async def _process_events(self, events: List[AzureActivityEvent], subscription: AzureSubscription):
        """Process and send Azure events"""
        for event in events:
            # Update metrics
            resource_provider = event.resource_provider.split('/')[0] if '/' in event.resource_provider else event.resource_provider
            azure_events_total.labels(subscription=subscription.subscription_name, resource_provider=resource_provider, operation=event.operation_name).inc()
            
            # Check for security alerts
            if event.security_relevant or event.risk_score >= 6:
                await self._create_security_alert(event, subscription)
            
            # Cache event for correlation
            await self._cache_event(event, subscription)
            
            # Send to Kafka
            await self._send_to_kafka(event, subscription)
    
    async def _create_security_alert(self, event: AzureActivityEvent, subscription: AzureSubscription):
        """Create security alert for high-risk events"""
        alert_types = []
        
        if event.threat_indicators:
            alert_types.extend(event.threat_indicators)
        if event.compliance_violations:
            alert_types.extend(event.compliance_violations)
        if event.risk_score >= 8:
            alert_types.append("high_risk_activity")
        
        for alert_type in alert_types:
            azure_security_alerts_total.labels(subscription=subscription.subscription_name, alert_type=alert_type).inc()
        
        # Create alert payload
        alert = {
            "alert_id": f"azure_{subscription.subscription_id}_{event.operation_id}",
            "timestamp": event.event_time.isoformat(),
            "subscription_id": subscription.subscription_id,
            "subscription_name": subscription.subscription_name,
            "environment": subscription.environment,
            "operation_name": event.operation_name,
            "resource_provider": event.resource_provider,
            "caller": event.caller,
            "caller_ip": event.caller_ip_address,
            "risk_score": event.risk_score,
            "investigation_priority": event.investigation_priority,
            "threat_indicators": event.threat_indicators,
            "compliance_violations": event.compliance_violations,
            "azure_region": event.azure_region,
            "raw_event": asdict(event)
        }
        
        # Send to high-priority topic
        self.kafka_producer.send("azure-security-alerts", alert)
        
        self.logger.warning("Azure security alert created",
                          subscription=subscription.subscription_name,
                          operation_name=event.operation_name,
                          risk_score=event.risk_score,
                          alert_types=alert_types)
    
    async def _cache_event(self, event: AzureActivityEvent, subscription: AzureSubscription):
        """Cache event for correlation analysis"""
        try:
            cache_key = f"azure:event:{subscription.subscription_id}:{event.operation_id}"
            cache_data = {
                "operation_name": event.operation_name,
                "resource_provider": event.resource_provider,
                "caller": event.caller,
                "caller_ip": event.caller_ip_address,
                "timestamp": event.event_time.isoformat(),
                "risk_score": event.risk_score,
                "security_relevant": event.security_relevant
            }
            
            # Store with TTL of 24 hours
            self.redis_client.setex(cache_key, 86400, json.dumps(cache_data))
            
        except Exception as e:
            self.logger.error("Failed to cache event", error=str(e))
    
    async def _send_to_kafka(self, event: AzureActivityEvent, subscription: AzureSubscription):
        """Send event to Kafka"""
        try:
            # Convert event to dict for JSON serialization
            message = asdict(event)
            message["timestamp"] = event.event_time.isoformat()
            message["subscription_name"] = subscription.subscription_name
            message["environment"] = subscription.environment
            message["tenant_id"] = "isectech"
            
            # Send to Kafka
            self.kafka_producer.send(
                self.config.config["kafka"]["topic"],
                value=message,
                key=f"{subscription.subscription_id}:{event.operation_id}"
            )
            
        except Exception as e:
            self.logger.error("Failed to send to Kafka", error=str(e))
    
    async def _monitoring_loop(self):
        """Monitoring and health check loop"""
        while self.running:
            try:
                # Update active subscriptions metric
                active_count = sum(1 for subscription in self.subscriptions.values() if subscription.enabled)
                active_subscriptions.set(active_count)
                
                # Perform health checks
                await self._health_check()
                
                self.logger.info("Health check completed", active_subscriptions=active_count)
                
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
        
        # Check Azure API connectivity for each subscription
        for subscription in self.subscriptions.values():
            if subscription.enabled:
                try:
                    credential = ClientSecretCredential(
                        tenant_id=subscription.tenant_id,
                        client_id=subscription.client_id,
                        client_secret=subscription.client_secret
                    )
                    
                    # Test with Resource Management client
                    resource_client = ResourceManagementClient(credential, subscription.subscription_id)
                    list(resource_client.resource_groups.list())
                    
                except Exception as e:
                    self.logger.error("Azure API health check failed", subscription=subscription.subscription_name, error=str(e))

# ═══════════════════════════════════════════════════════════════════════════════
# MAIN EXECUTION
# ═══════════════════════════════════════════════════════════════════════════════

async def main():
    """Main execution function"""
    collector = AzureActivityCollector()
    
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