#!/usr/bin/env python3
"""
iSECTECH SIEM AWS CloudTrail Collector
High-performance AWS security event collection and real-time analysis
"""

import asyncio
import json
import logging
import gzip
import io
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
from pathlib import Path
import yaml

# Third-party imports
import boto3
import botocore
from kafka import KafkaProducer
from prometheus_client import Counter, Histogram, Gauge, start_http_server
import redis
import structlog

# ═══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION AND DATA STRUCTURES
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class AWSAccount:
    """AWS account configuration"""
    account_id: str
    account_name: str
    access_key_id: str
    secret_access_key: str
    session_token: Optional[str] = None
    region: str = "us-east-1"
    cloudtrail_bucket: str = ""
    cloudtrail_prefix: str = "AWSLogs"
    vpc_flow_logs_group: str = ""
    guardduty_detector_id: str = ""
    config_bucket: str = ""
    enabled: bool = True
    criticality: str = "medium"
    environment: str = "production"
    tags: List[str] = None

    def __post_init__(self):
        if self.tags is None:
            self.tags = []

@dataclass
class CloudTrailEvent:
    """CloudTrail event structure"""
    event_time: datetime
    event_source: str
    event_name: str
    aws_region: str
    source_ip_address: str
    user_agent: str
    user_identity: Dict[str, Any]
    request_parameters: Dict[str, Any]
    response_elements: Dict[str, Any]
    event_id: str
    event_type: str
    recipient_account_id: str
    service_event_details: Dict[str, Any]
    shared_event_id: Optional[str] = None
    vpc_endpoint_id: Optional[str] = None
    error_code: Optional[str] = None
    error_message: Optional[str] = None
    request_id: Optional[str] = None
    management_event: bool = True
    read_only: bool = True
    resources: List[Dict[str, Any]] = None
    
    # Enhanced security fields
    risk_score: int = 1
    security_relevant: bool = False
    threat_indicators: List[str] = None
    compliance_violations: List[str] = None
    investigation_priority: str = "low"
    
    def __post_init__(self):
        if self.resources is None:
            self.resources = []
        if self.threat_indicators is None:
            self.threat_indicators = []
        if self.compliance_violations is None:
            self.compliance_violations = []

class AWSCollectorConfig:
    """Configuration management for AWS collector"""
    
    def __init__(self, config_file: str = "/etc/isectech-siem/aws-collector.yaml"):
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
                "metrics_port": 9164
            },
            "kafka": {
                "bootstrap_servers": ["kafka-1.isectech.local:9092"],
                "topic": "aws-security-events",
                "batch_size": 1000,
                "linger_ms": 1000,
                "compression_type": "gzip"
            },
            "redis": {
                "host": "redis.isectech.local",
                "port": 6379,
                "db": 4,
                "password": None
            },
            "security": {
                "high_risk_events": [
                    "ConsoleLogin",
                    "AssumeRole",
                    "CreateUser",
                    "DeleteUser",
                    "AttachUserPolicy",
                    "CreateRole",
                    "PutBucketPolicy",
                    "DeleteBucket",
                    "StopInstances",
                    "TerminateInstances"
                ],
                "critical_services": [
                    "iam",
                    "s3",
                    "ec2",
                    "rds",
                    "lambda",
                    "sts",
                    "cloudformation"
                ],
                "compliance_events": [
                    "PutBucketEncryption",
                    "DeleteBucketEncryption",
                    "PutBucketLogging",
                    "DeleteBucketLogging",
                    "EnableConfigurationRecorder",
                    "StopConfigurationRecorder"
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

# High-risk CloudTrail events with base risk scores
HIGH_RISK_EVENTS = {
    # Identity and Access Management
    "ConsoleLogin": 3,
    "AssumeRole": 4,
    "AssumeRoleWithSAML": 5,
    "AssumeRoleWithWebIdentity": 5,
    "CreateUser": 6,
    "DeleteUser": 7,
    "AttachUserPolicy": 6,
    "DetachUserPolicy": 5,
    "PutUserPolicy": 6,
    "DeleteUserPolicy": 5,
    "CreateRole": 5,
    "DeleteRole": 6,
    "CreateAccessKey": 6,
    "DeleteAccessKey": 5,
    "UpdateAccessKey": 4,
    
    # S3 Security Events
    "PutBucketPolicy": 5,
    "DeleteBucketPolicy": 6,
    "PutBucketAcl": 5,
    "PutObjectAcl": 4,
    "DeleteBucket": 7,
    "CreateBucket": 3,
    "PutBucketEncryption": 3,
    "DeleteBucketEncryption": 8,
    
    # EC2 Security Events
    "RunInstances": 4,
    "TerminateInstances": 6,
    "StopInstances": 5,
    "ModifyInstanceAttribute": 4,
    "AuthorizeSecurityGroupIngress": 5,
    "RevokeSecurityGroupIngress": 4,
    "CreateSecurityGroup": 4,
    "DeleteSecurityGroup": 5,
    
    # Network Security
    "CreateVpc": 3,
    "DeleteVpc": 6,
    "CreateInternetGateway": 4,
    "AttachInternetGateway": 5,
    "CreateNatGateway": 4,
    "DeleteNatGateway": 5,
    "ModifyVpcAttribute": 4,
    
    # Database Security
    "CreateDBInstance": 4,
    "DeleteDBInstance": 7,
    "ModifyDBInstance": 4,
    "CreateDBSnapshot": 3,
    "DeleteDBSnapshot": 5,
    "RestoreDBInstanceFromDBSnapshot": 5,
    
    # CloudFormation and Infrastructure
    "CreateStack": 4,
    "UpdateStack": 5,
    "DeleteStack": 6,
    
    # Lambda and Serverless
    "CreateFunction": 3,
    "UpdateFunctionCode": 4,
    "DeleteFunction": 5,
    "InvokeFunction": 2,
    
    # Logging and Monitoring
    "StopLogging": 8,
    "DeleteTrail": 9,
    "PutBucketLogging": 3,
    "DeleteBucketLogging": 7,
    "StopConfigurationRecorder": 7,
    "DeleteConfigRule": 6
}

# Suspicious source IP patterns
SUSPICIOUS_IP_PATTERNS = [
    "tor-exit-nodes",
    "known-malicious",
    "cloud-providers",
    "anonymizers"
]

# Error codes that indicate security issues
SECURITY_ERROR_CODES = [
    "AccessDenied",
    "UnauthorizedOperation", 
    "InvalidUserID.NotFound",
    "SigninFailure",
    "TokenRefreshRequired",
    "CredentialsNotFound"
]

# ═══════════════════════════════════════════════════════════════════════════════
# METRICS AND MONITORING
# ═══════════════════════════════════════════════════════════════════════════════

# Prometheus metrics
aws_events_total = Counter('aws_events_total', 'Total AWS events processed', ['account', 'service', 'event_name'])
aws_security_alerts_total = Counter('aws_security_alerts_total', 'Security alerts from AWS events', ['account', 'alert_type'])
aws_collection_duration = Histogram('aws_collection_duration_seconds', 'AWS collection duration', ['account', 'service'])
aws_api_errors_total = Counter('aws_api_errors_total', 'AWS API errors', ['account', 'service', 'error_type'])
active_accounts = Gauge('aws_active_accounts', 'Number of active AWS accounts being monitored')

# ═══════════════════════════════════════════════════════════════════════════════
# AWS COLLECTOR CLASS
# ═══════════════════════════════════════════════════════════════════════════════

class AWSCloudTrailCollector:
    """High-performance AWS CloudTrail and security event collector"""
    
    def __init__(self, config_file: str = "/etc/isectech-siem/aws-collector.yaml"):
        self.config = AWSCollectorConfig(config_file)
        self.logger = self._setup_logging()
        self.accounts: Dict[str, AWSAccount] = {}
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
        
        return structlog.get_logger("aws_collector")
    
    async def initialize(self):
        """Initialize collector components"""
        self.logger.info("Initializing AWS CloudTrail collector")
        
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
        
        # Load AWS account configurations
        await self._load_accounts()
        
        # Start Prometheus metrics server
        start_http_server(self.config.config["collector"]["metrics_port"])
        
        self.logger.info("AWS collector initialized", accounts_count=len(self.accounts))
    
    async def _load_accounts(self):
        """Load AWS account configurations"""
        # In production, this would load from a secure configuration store
        sample_accounts = [
            AWSAccount(
                account_id="123456789012",
                account_name="production-main",
                access_key_id="AKIA...",  # Would be from secure store
                secret_access_key="...",  # Would be from secure store
                region="us-east-1",
                cloudtrail_bucket="isectech-cloudtrail-prod",
                cloudtrail_prefix="AWSLogs/123456789012/CloudTrail",
                vpc_flow_logs_group="/aws/vpc/flowlogs",
                guardduty_detector_id="abc123def456",
                config_bucket="isectech-config-prod",
                criticality="critical",
                environment="production",
                tags=["production", "critical", "main"]
            ),
            AWSAccount(
                account_id="123456789013",
                account_name="development",
                access_key_id="AKIA...",
                secret_access_key="...",
                region="us-west-2",
                cloudtrail_bucket="isectech-cloudtrail-dev",
                cloudtrail_prefix="AWSLogs/123456789013/CloudTrail",
                criticality="medium",
                environment="development",
                tags=["development", "non-production"]
            )
        ]
        
        for account in sample_accounts:
            self.accounts[account.account_id] = account
    
    async def start(self):
        """Start the AWS collector"""
        self.logger.info("Starting AWS CloudTrail collector")
        self.running = True
        
        # Schedule collection tasks for each account
        for account_id, account in self.accounts.items():
            if account.enabled:
                task = asyncio.create_task(self._account_collection_loop(account))
                self.tasks.append(task)
        
        # Start monitoring task
        self.tasks.append(asyncio.create_task(self._monitoring_loop()))
        
        # Wait for all tasks
        await asyncio.gather(*self.tasks, return_exceptions=True)
    
    async def stop(self):
        """Stop the AWS collector"""
        self.logger.info("Stopping AWS CloudTrail collector")
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
    
    async def _account_collection_loop(self, account: AWSAccount):
        """Main collection loop for an AWS account"""
        logger = self.logger.bind(account=account.account_name)
        
        while self.running:
            try:
                start_time = time.time()
                
                # Collect CloudTrail events
                events = await self._collect_cloudtrail_events(account)
                
                # Collect GuardDuty findings
                if account.guardduty_detector_id:
                    guardduty_findings = await self._collect_guardduty_findings(account)
                    events.extend(guardduty_findings)
                
                # Collect Config compliance data
                if account.config_bucket:
                    config_events = await self._collect_config_events(account)
                    events.extend(config_events)
                
                # Process and send results
                await self._process_events(events, account)
                
                collection_duration = time.time() - start_time
                aws_collection_duration.labels(account=account.account_name, service="cloudtrail").observe(collection_duration)
                
                logger.debug("Collection completed", 
                           events_collected=len(events),
                           duration=collection_duration)
                
            except Exception as e:
                aws_api_errors_total.labels(account=account.account_name, service="cloudtrail", error_type=type(e).__name__).inc()
                logger.error("Collection failed", error=str(e))
            
            # Wait for next collection interval
            await asyncio.sleep(self.config.config["collector"]["collection_interval"])
    
    async def _collect_cloudtrail_events(self, account: AWSAccount) -> List[CloudTrailEvent]:
        """Collect CloudTrail events from S3"""
        events = []
        
        try:
            # Create boto3 session
            session = boto3.Session(
                aws_access_key_id=account.access_key_id,
                aws_secret_access_key=account.secret_access_key,
                aws_session_token=account.session_token,
                region_name=account.region
            )
            
            s3_client = session.client('s3')
            
            # Get last processed timestamp from Redis
            last_processed_key = f"aws:cloudtrail:{account.account_id}:last_processed"
            last_processed = self.redis_client.get(last_processed_key)
            if last_processed:
                last_processed = datetime.fromisoformat(last_processed)
            else:
                # Start from 1 hour ago if no previous state
                last_processed = datetime.now(timezone.utc).replace(hour=datetime.now().hour-1, minute=0, second=0, microsecond=0)
            
            # List CloudTrail log files
            prefix = f"{account.cloudtrail_prefix}/"
            response = s3_client.list_objects_v2(
                Bucket=account.cloudtrail_bucket,
                Prefix=prefix,
                StartAfter=f"{prefix}{last_processed.strftime('%Y/%m/%d')}"
            )
            
            if 'Contents' not in response:
                return events
            
            # Process each log file
            for obj in response['Contents']:
                if obj['LastModified'].replace(tzinfo=timezone.utc) <= last_processed:
                    continue
                
                # Download and decompress log file
                log_content = s3_client.get_object(Bucket=account.cloudtrail_bucket, Key=obj['Key'])
                
                if obj['Key'].endswith('.gz'):
                    log_data = gzip.decompress(log_content['Body'].read()).decode('utf-8')
                else:
                    log_data = log_content['Body'].read().decode('utf-8')
                
                # Parse CloudTrail records
                try:
                    cloudtrail_data = json.loads(log_data)
                    for record in cloudtrail_data.get('Records', []):
                        event = self._parse_cloudtrail_record(record, account)
                        if event:
                            events.append(event)
                except json.JSONDecodeError:
                    self.logger.error("Invalid JSON in CloudTrail log", key=obj['Key'])
            
            # Update last processed timestamp
            current_time = datetime.now(timezone.utc)
            self.redis_client.set(last_processed_key, current_time.isoformat())
            
        except Exception as e:
            self.logger.error("Failed to collect CloudTrail events", account=account.account_name, error=str(e))
        
        return events
    
    def _parse_cloudtrail_record(self, record: Dict[str, Any], account: AWSAccount) -> Optional[CloudTrailEvent]:
        """Parse a CloudTrail record into our event structure"""
        try:
            event = CloudTrailEvent(
                event_time=datetime.fromisoformat(record['eventTime'].replace('Z', '+00:00')),
                event_source=record.get('eventSource', ''),
                event_name=record.get('eventName', ''),
                aws_region=record.get('awsRegion', ''),
                source_ip_address=record.get('sourceIPAddress', ''),
                user_agent=record.get('userAgent', ''),
                user_identity=record.get('userIdentity', {}),
                request_parameters=record.get('requestParameters', {}),
                response_elements=record.get('responseElements', {}),
                event_id=record.get('eventID', ''),
                event_type=record.get('eventType', ''),
                recipient_account_id=record.get('recipientAccountId', ''),
                service_event_details=record.get('serviceEventDetails', {}),
                shared_event_id=record.get('sharedEventId'),
                vpc_endpoint_id=record.get('vpcEndpointId'),
                error_code=record.get('errorCode'),
                error_message=record.get('errorMessage'),
                request_id=record.get('requestID'),
                management_event=record.get('managementEvent', True),
                read_only=record.get('readOnly', True),
                resources=record.get('resources', [])
            )
            
            # Perform security analysis
            self._analyze_event_security(event, account)
            
            return event
            
        except Exception as e:
            self.logger.error("Failed to parse CloudTrail record", error=str(e), record_id=record.get('eventID'))
            return None
    
    def _analyze_event_security(self, event: CloudTrailEvent, account: AWSAccount):
        """Perform security analysis on the event"""
        # Base risk score from event type
        event.risk_score = HIGH_RISK_EVENTS.get(event.event_name, 1)
        
        # Mark as security relevant if it's a high-risk event
        if event.event_name in HIGH_RISK_EVENTS:
            event.security_relevant = True
        
        # Check for critical services
        service = event.event_source.split('.')[0] if '.' in event.event_source else event.event_source
        if service in self.config.config["security"]["critical_services"]:
            event.risk_score += 1
            event.security_relevant = True
        
        # Analyze error conditions
        if event.error_code:
            if event.error_code in SECURITY_ERROR_CODES:
                event.risk_score += 2
                event.threat_indicators.append(f"security_error_{event.error_code}")
            
            # Multiple failed attempts
            if event.error_code == "SigninFailure":
                event.risk_score += 3
                event.threat_indicators.append("authentication_failure")
        
        # Analyze source IP
        if event.source_ip_address:
            # Check for suspicious IP patterns (would integrate with threat intelligence)
            if self._is_suspicious_ip(event.source_ip_address):
                event.risk_score += 3
                event.threat_indicators.append("suspicious_source_ip")
            
            # Check for geographic anomalies
            if self._is_geographic_anomaly(event.source_ip_address, account):
                event.risk_score += 2
                event.threat_indicators.append("geographic_anomaly")
        
        # Analyze user identity
        user_type = event.user_identity.get('type', '')
        if user_type == 'Root':
            event.risk_score += 3
            event.threat_indicators.append("root_account_usage")
        elif user_type == 'AssumedRole':
            # Check for privilege escalation patterns
            if self._is_privilege_escalation(event):
                event.risk_score += 4
                event.threat_indicators.append("privilege_escalation")
        
        # Analyze time-based patterns
        if self._is_off_hours_activity(event.event_time):
            event.risk_score += 1
            event.threat_indicators.append("off_hours_activity")
        
        # Check for compliance violations
        if event.event_name in self.config.config["security"]["compliance_events"]:
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
        """Check if IP address is suspicious (stub - would integrate with threat intel)"""
        # In production, this would check against threat intelligence feeds
        # For now, check for RFC 1918 private addresses from public services
        private_ranges = ["10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", 
                         "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.",
                         "172.27.", "172.28.", "172.29.", "172.30.", "172.31.", "192.168."]
        
        return any(ip_address.startswith(private) for private in private_ranges)
    
    def _is_geographic_anomaly(self, ip_address: str, account: AWSAccount) -> bool:
        """Check for geographic anomalies (stub)"""
        # In production, this would use GeoIP databases and user baseline profiles
        return False
    
    def _is_privilege_escalation(self, event: CloudTrailEvent) -> bool:
        """Detect privilege escalation patterns"""
        if event.event_name in ["AttachUserPolicy", "PutUserPolicy", "AttachRolePolicy", "PutRolePolicy"]:
            # Check if granting administrative policies
            request_params = event.request_parameters
            policy_arn = request_params.get('policyArn', '')
            if 'AdministratorAccess' in policy_arn or 'PowerUserAccess' in policy_arn:
                return True
            
            # Check policy document for administrative permissions
            policy_document = request_params.get('policyDocument', '')
            if isinstance(policy_document, str):
                try:
                    policy = json.loads(policy_document)
                    for statement in policy.get('Statement', []):
                        if statement.get('Effect') == 'Allow' and statement.get('Action') == '*':
                            return True
                except json.JSONDecodeError:
                    pass
        
        return False
    
    def _is_off_hours_activity(self, event_time: datetime) -> bool:
        """Check if activity occurred during off hours"""
        # Business hours: 8 AM to 6 PM Monday-Friday
        hour = event_time.hour
        weekday = event_time.weekday()  # 0=Monday, 6=Sunday
        
        return hour < 8 or hour > 18 or weekday >= 5
    
    def _is_compliance_violation(self, event: CloudTrailEvent) -> bool:
        """Check for compliance violations"""
        # Example: Disabling encryption on S3 buckets
        if event.event_name == "DeleteBucketEncryption":
            return True
        
        # Example: Stopping CloudTrail logging
        if event.event_name == "StopLogging":
            return True
        
        # Example: Disabling Config recorder
        if event.event_name == "StopConfigurationRecorder":
            return True
        
        return False
    
    async def _collect_guardduty_findings(self, account: AWSAccount) -> List[CloudTrailEvent]:
        """Collect GuardDuty findings"""
        findings = []
        
        try:
            session = boto3.Session(
                aws_access_key_id=account.access_key_id,
                aws_secret_access_key=account.secret_access_key,
                aws_session_token=account.session_token,
                region_name=account.region
            )
            
            guardduty_client = session.client('guardduty')
            
            # Get findings from the last collection interval
            response = guardduty_client.list_findings(
                DetectorId=account.guardduty_detector_id,
                FindingCriteria={
                    'Criterion': {
                        'updatedAt': {
                            'GreaterThan': int((datetime.now(timezone.utc).timestamp() - 
                                              self.config.config["collector"]["collection_interval"]) * 1000)
                        }
                    }
                }
            )
            
            if response['FindingIds']:
                findings_details = guardduty_client.get_findings(
                    DetectorId=account.guardduty_detector_id,
                    FindingIds=response['FindingIds']
                )
                
                for finding in findings_details['Findings']:
                    event = self._parse_guardduty_finding(finding, account)
                    if event:
                        findings.append(event)
        
        except Exception as e:
            self.logger.error("Failed to collect GuardDuty findings", account=account.account_name, error=str(e))
        
        return findings
    
    def _parse_guardduty_finding(self, finding: Dict[str, Any], account: AWSAccount) -> Optional[CloudTrailEvent]:
        """Parse GuardDuty finding into CloudTrail event format"""
        try:
            service = finding.get('Service', {})
            
            event = CloudTrailEvent(
                event_time=datetime.fromisoformat(finding['UpdatedAt'].replace('Z', '+00:00')),
                event_source="guardduty.amazonaws.com",
                event_name=f"GuardDuty_{finding['Type'].replace('/', '_')}",
                aws_region=finding['Region'],
                source_ip_address=service.get('RemoteIpDetails', {}).get('IpAddressV4', ''),
                user_agent="GuardDuty",
                user_identity={"type": "AWSService"},
                request_parameters={},
                response_elements={},
                event_id=finding['Id'],
                event_type="GuardDuty Finding",
                recipient_account_id=finding['AccountId'],
                service_event_details=finding,
                management_event=False,
                read_only=True,
                risk_score=int(finding['Severity'] / 2) + 1,  # Scale 0-10 to 1-6
                security_relevant=True,
                threat_indicators=[finding['Type']],
                investigation_priority="high" if finding['Severity'] > 7 else "medium"
            )
            
            return event
            
        except Exception as e:
            self.logger.error("Failed to parse GuardDuty finding", error=str(e), finding_id=finding.get('Id'))
            return None
    
    async def _collect_config_events(self, account: AWSAccount) -> List[CloudTrailEvent]:
        """Collect AWS Config compliance events"""
        events = []
        
        try:
            session = boto3.Session(
                aws_access_key_id=account.access_key_id,
                aws_secret_access_key=account.secret_access_key,
                aws_session_token=account.session_token,
                region_name=account.region
            )
            
            config_client = session.client('config')
            
            # Get compliance details for resources
            response = config_client.describe_compliance_by_config_rule()
            
            for compliance in response['ComplianceByConfigRules']:
                if compliance['Compliance']['ComplianceType'] == 'NON_COMPLIANT':
                    event = CloudTrailEvent(
                        event_time=datetime.now(timezone.utc),
                        event_source="config.amazonaws.com",
                        event_name="ConfigComplianceViolation",
                        aws_region=account.region,
                        source_ip_address="",
                        user_agent="AWSConfig",
                        user_identity={"type": "AWSService"},
                        request_parameters={"configRuleName": compliance['ConfigRuleName']},
                        response_elements={"compliance": compliance['Compliance']},
                        event_id=f"config_{compliance['ConfigRuleName']}_{int(time.time())}",
                        event_type="Config Compliance",
                        recipient_account_id=account.account_id,
                        service_event_details=compliance,
                        management_event=False,
                        read_only=True,
                        risk_score=5,
                        security_relevant=True,
                        compliance_violations=["config_rule_violation"],
                        investigation_priority="medium"
                    )
                    events.append(event)
        
        except Exception as e:
            self.logger.error("Failed to collect Config events", account=account.account_name, error=str(e))
        
        return events
    
    async def _process_events(self, events: List[CloudTrailEvent], account: AWSAccount):
        """Process and send AWS events"""
        for event in events:
            # Update metrics
            service = event.event_source.split('.')[0] if '.' in event.event_source else event.event_source
            aws_events_total.labels(account=account.account_name, service=service, event_name=event.event_name).inc()
            
            # Check for security alerts
            if event.security_relevant or event.risk_score >= 6:
                await self._create_security_alert(event, account)
            
            # Cache event for correlation
            await self._cache_event(event, account)
            
            # Send to Kafka
            await self._send_to_kafka(event, account)
    
    async def _create_security_alert(self, event: CloudTrailEvent, account: AWSAccount):
        """Create security alert for high-risk events"""
        alert_types = []
        
        if event.threat_indicators:
            alert_types.extend(event.threat_indicators)
        if event.compliance_violations:
            alert_types.extend(event.compliance_violations)
        if event.risk_score >= 8:
            alert_types.append("high_risk_activity")
        
        for alert_type in alert_types:
            aws_security_alerts_total.labels(account=account.account_name, alert_type=alert_type).inc()
        
        # Create alert payload
        alert = {
            "alert_id": f"aws_{account.account_id}_{event.event_id}",
            "timestamp": event.event_time.isoformat(),
            "account_id": account.account_id,
            "account_name": account.account_name,
            "environment": account.environment,
            "event_name": event.event_name,
            "event_source": event.event_source,
            "source_ip": event.source_ip_address,
            "user_identity": event.user_identity,
            "risk_score": event.risk_score,
            "investigation_priority": event.investigation_priority,
            "threat_indicators": event.threat_indicators,
            "compliance_violations": event.compliance_violations,
            "aws_region": event.aws_region,
            "raw_event": asdict(event)
        }
        
        # Send to high-priority topic
        self.kafka_producer.send("aws-security-alerts", alert)
        
        self.logger.warning("AWS security alert created",
                          account=account.account_name,
                          event_name=event.event_name,
                          risk_score=event.risk_score,
                          alert_types=alert_types)
    
    async def _cache_event(self, event: CloudTrailEvent, account: AWSAccount):
        """Cache event for correlation analysis"""
        try:
            cache_key = f"aws:event:{account.account_id}:{event.event_id}"
            cache_data = {
                "event_name": event.event_name,
                "event_source": event.event_source,
                "source_ip": event.source_ip_address,
                "user_identity": event.user_identity,
                "timestamp": event.event_time.isoformat(),
                "risk_score": event.risk_score,
                "security_relevant": event.security_relevant
            }
            
            # Store with TTL of 24 hours
            self.redis_client.setex(cache_key, 86400, json.dumps(cache_data))
            
        except Exception as e:
            self.logger.error("Failed to cache event", error=str(e))
    
    async def _send_to_kafka(self, event: CloudTrailEvent, account: AWSAccount):
        """Send event to Kafka"""
        try:
            # Convert event to dict for JSON serialization
            message = asdict(event)
            message["timestamp"] = event.event_time.isoformat()
            message["account_name"] = account.account_name
            message["environment"] = account.environment
            message["tenant_id"] = "isectech"
            
            # Send to Kafka
            self.kafka_producer.send(
                self.config.config["kafka"]["topic"],
                value=message,
                key=f"{account.account_id}:{event.event_id}"
            )
            
        except Exception as e:
            self.logger.error("Failed to send to Kafka", error=str(e))
    
    async def _monitoring_loop(self):
        """Monitoring and health check loop"""
        while self.running:
            try:
                # Update active accounts metric
                active_count = sum(1 for account in self.accounts.values() if account.enabled)
                active_accounts.set(active_count)
                
                # Perform health checks
                await self._health_check()
                
                self.logger.info("Health check completed", active_accounts=active_count)
                
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
        
        # Check AWS API connectivity for each account
        for account in self.accounts.values():
            if account.enabled:
                try:
                    session = boto3.Session(
                        aws_access_key_id=account.access_key_id,
                        aws_secret_access_key=account.secret_access_key,
                        aws_session_token=account.session_token,
                        region_name=account.region
                    )
                    sts_client = session.client('sts')
                    sts_client.get_caller_identity()
                except Exception as e:
                    self.logger.error("AWS API health check failed", account=account.account_name, error=str(e))

# ═══════════════════════════════════════════════════════════════════════════════
# MAIN EXECUTION
# ═══════════════════════════════════════════════════════════════════════════════

async def main():
    """Main execution function"""
    collector = AWSCloudTrailCollector()
    
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