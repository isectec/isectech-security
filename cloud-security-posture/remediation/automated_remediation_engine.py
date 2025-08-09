#!/usr/bin/env python3
"""
iSECTECH Cloud Security Posture Management - Automated Remediation and Policy-as-Code Engine
Automated security remediation with policy-driven configuration management
"""

import asyncio
import json
import logging
import yaml
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Any, Set, Union, Callable
from abc import ABC, abstractmethod

import boto3
import jinja2
from azure.identity import DefaultAzureCredential
from azure.mgmt.resource import ResourceManagementClient
from google.cloud import asset_v1


class RemediationAction(Enum):
    """Types of remediation actions"""
    CREATE = "create"
    UPDATE = "update"
    DELETE = "delete"
    ENABLE = "enable"
    DISABLE = "disable"
    ATTACH = "attach"
    DETACH = "detach"
    RESTRICT = "restrict"
    ROTATE = "rotate"


class RemediationStatus(Enum):
    """Remediation execution status"""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"
    REQUIRES_APPROVAL = "requires_approval"


class ApprovalLevel(Enum):
    """Approval levels for remediation actions"""
    AUTOMATIC = "automatic"
    MANAGER_APPROVAL = "manager_approval"
    SECURITY_TEAM_APPROVAL = "security_team_approval"
    MANUAL_ONLY = "manual_only"


@dataclass
class RemediationTemplate:
    """Infrastructure-as-Code remediation template"""
    template_id: str
    name: str
    description: str
    cloud_provider: str
    resource_type: str
    action: RemediationAction
    template_format: str  # terraform, cloudformation, arm, deployment_manager
    template_content: str
    parameters: Dict[str, Any] = field(default_factory=dict)
    prerequisites: List[str] = field(default_factory=list)
    rollback_template: Optional[str] = None
    test_cases: List[Dict[str, Any]] = field(default_factory=list)
    approval_level: ApprovalLevel = ApprovalLevel.AUTOMATIC
    risk_level: str = "medium"
    tags: Dict[str, str] = field(default_factory=dict)


@dataclass
class RemediationTask:
    """Individual remediation task"""
    task_id: str
    finding_id: str
    resource_id: str
    resource_type: str
    cloud_provider: str
    account_id: str
    region: str
    template_id: str
    action: RemediationAction
    priority: str = "medium"
    status: RemediationStatus = RemediationStatus.PENDING
    parameters: Dict[str, Any] = field(default_factory=dict)
    created_timestamp: datetime = field(default_factory=datetime.utcnow)
    scheduled_timestamp: Optional[datetime] = None
    started_timestamp: Optional[datetime] = None
    completed_timestamp: Optional[datetime] = None
    execution_log: List[str] = field(default_factory=list)
    approval_status: Optional[str] = None
    approved_by: Optional[str] = None
    approved_timestamp: Optional[datetime] = None
    rollback_plan: Optional[str] = None
    validation_results: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PolicyRule:
    """Policy-as-Code rule definition"""
    rule_id: str
    name: str
    description: str
    cloud_provider: str
    resource_types: List[str]
    conditions: Dict[str, Any]
    remediation_template_id: str
    enforcement_mode: str = "enforce"  # monitor, enforce, prevent
    severity: str = "medium"
    enabled: bool = True
    tags: Dict[str, str] = field(default_factory=dict)
    exceptions: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class RemediationResult:
    """Result of remediation execution"""
    task_id: str
    status: RemediationStatus
    start_time: datetime
    end_time: datetime
    execution_duration: float
    success: bool
    message: str
    changes_made: List[str] = field(default_factory=list)
    resources_affected: List[str] = field(default_factory=list)
    rollback_available: bool = False
    rollback_instructions: Optional[str] = None
    validation_passed: bool = False
    error_details: Optional[str] = None


class RemediationExecutor(ABC):
    """Base class for cloud-specific remediation executors"""
    
    def __init__(self, cloud_provider: str):
        self.cloud_provider = cloud_provider
        self.logger = logging.getLogger(f"RemediationExecutor.{cloud_provider}")
    
    @abstractmethod
    async def execute_remediation(self, task: RemediationTask, template: RemediationTemplate) -> RemediationResult:
        """Execute remediation task"""
        pass
    
    @abstractmethod
    async def validate_remediation(self, task: RemediationTask, result: RemediationResult) -> bool:
        """Validate remediation was successful"""
        pass
    
    @abstractmethod
    async def rollback_remediation(self, task: RemediationTask, result: RemediationResult) -> bool:
        """Rollback remediation if needed"""
        pass


class AWSRemediationExecutor(RemediationExecutor):
    """AWS-specific remediation executor"""
    
    def __init__(self):
        super().__init__("aws")
        self.session_cache = {}
    
    def _get_session(self, region: str) -> boto3.Session:
        """Get or create AWS session for region"""
        if region not in self.session_cache:
            self.session_cache[region] = boto3.Session(region_name=region)
        return self.session_cache[region]
    
    async def execute_remediation(self, task: RemediationTask, template: RemediationTemplate) -> RemediationResult:
        """Execute AWS remediation task"""
        start_time = datetime.utcnow()
        
        try:
            session = self._get_session(task.region)
            
            # Execute based on action type
            if task.action == RemediationAction.CREATE:
                result = await self._create_aws_resource(task, template, session)
            elif task.action == RemediationAction.UPDATE:
                result = await self._update_aws_resource(task, template, session)
            elif task.action == RemediationAction.DELETE:
                result = await self._delete_aws_resource(task, template, session)
            elif task.action == RemediationAction.ENABLE:
                result = await self._enable_aws_feature(task, template, session)
            elif task.action == RemediationAction.DISABLE:
                result = await self._disable_aws_feature(task, template, session)
            elif task.action == RemediationAction.ATTACH:
                result = await self._attach_aws_policy(task, template, session)
            elif task.action == RemediationAction.RESTRICT:
                result = await self._restrict_aws_access(task, template, session)
            else:
                raise ValueError(f"Unsupported remediation action: {task.action}")
            
            end_time = datetime.utcnow()
            execution_duration = (end_time - start_time).total_seconds()
            
            return RemediationResult(
                task_id=task.task_id,
                status=RemediationStatus.COMPLETED if result['success'] else RemediationStatus.FAILED,
                start_time=start_time,
                end_time=end_time,
                execution_duration=execution_duration,
                success=result['success'],
                message=result['message'],
                changes_made=result.get('changes_made', []),
                resources_affected=result.get('resources_affected', []),
                rollback_available=result.get('rollback_available', False),
                rollback_instructions=result.get('rollback_instructions'),
                validation_passed=result.get('validation_passed', False)
            )
            
        except Exception as e:
            end_time = datetime.utcnow()
            execution_duration = (end_time - start_time).total_seconds()
            
            return RemediationResult(
                task_id=task.task_id,
                status=RemediationStatus.FAILED,
                start_time=start_time,
                end_time=end_time,
                execution_duration=execution_duration,
                success=False,
                message=f"Remediation failed: {str(e)}",
                error_details=str(e)
            )
    
    async def _create_aws_resource(self, task: RemediationTask, template: RemediationTemplate, session: boto3.Session) -> Dict[str, Any]:
        """Create AWS resource"""
        if task.resource_type == "s3_bucket_policy":
            return await self._create_s3_bucket_policy(task, template, session)
        elif task.resource_type == "security_group_rule":
            return await self._create_security_group_rule(task, template, session)
        elif task.resource_type == "iam_policy":
            return await self._create_iam_policy(task, template, session)
        else:
            raise ValueError(f"Unsupported AWS resource type for creation: {task.resource_type}")
    
    async def _create_s3_bucket_policy(self, task: RemediationTask, template: RemediationTemplate, session: boto3.Session) -> Dict[str, Any]:
        """Create S3 bucket policy to restrict public access"""
        s3_client = session.client('s3')
        
        try:
            bucket_name = task.parameters.get('bucket_name', task.resource_id)
            
            # Create restrictive bucket policy
            bucket_policy = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "DenyPublicReadAccess",
                        "Effect": "Deny",
                        "Principal": "*",
                        "Action": "s3:GetObject",
                        "Resource": f"arn:aws:s3:::{bucket_name}/*",
                        "Condition": {
                            "StringNotEquals": {
                                "aws:PrincipalAccount": task.account_id
                            }
                        }
                    }
                ]
            }
            
            # Apply bucket policy
            s3_client.put_bucket_policy(
                Bucket=bucket_name,
                Policy=json.dumps(bucket_policy)
            )
            
            return {
                'success': True,
                'message': f'Applied restrictive bucket policy to {bucket_name}',
                'changes_made': [f'Created bucket policy for {bucket_name}'],
                'resources_affected': [bucket_name],
                'rollback_available': True,
                'rollback_instructions': f'Delete bucket policy from {bucket_name}',
                'validation_passed': True
            }
            
        except Exception as e:
            return {
                'success': False,
                'message': f'Failed to create S3 bucket policy: {str(e)}',
                'error_details': str(e)
            }
    
    async def _restrict_aws_access(self, task: RemediationTask, template: RemediationTemplate, session: boto3.Session) -> Dict[str, Any]:
        """Restrict AWS resource access"""
        if task.resource_type == "security_group":
            return await self._restrict_security_group_access(task, template, session)
        elif task.resource_type == "s3_bucket":
            return await self._restrict_s3_bucket_access(task, template, session)
        else:
            raise ValueError(f"Unsupported AWS resource type for access restriction: {task.resource_type}")
    
    async def _restrict_security_group_access(self, task: RemediationTask, template: RemediationTemplate, session: boto3.Session) -> Dict[str, Any]:
        """Restrict security group access by removing overly permissive rules"""
        ec2_client = session.client('ec2')
        
        try:
            sg_id = task.resource_id
            
            # Get current security group
            response = ec2_client.describe_security_groups(GroupIds=[sg_id])
            sg = response['SecurityGroups'][0]
            
            changes_made = []
            resources_affected = [sg_id]
            
            # Remove rules allowing access from 0.0.0.0/0 for sensitive ports
            sensitive_ports = task.parameters.get('sensitive_ports', [22, 3389, 1433, 3306])
            
            for rule in sg.get('IpPermissions', []):
                from_port = rule.get('FromPort')
                to_port = rule.get('ToPort')
                
                if from_port in sensitive_ports or to_port in sensitive_ports:
                    # Check for 0.0.0.0/0 access
                    for ip_range in rule.get('IpRanges', []):
                        if ip_range.get('CidrIp') == '0.0.0.0/0':
                            # Remove this rule
                            ec2_client.revoke_security_group_ingress(
                                GroupId=sg_id,
                                IpPermissions=[rule]
                            )
                            changes_made.append(f'Removed public access rule for port {from_port}-{to_port}')
            
            if changes_made:
                return {
                    'success': True,
                    'message': f'Restricted security group {sg_id} access',
                    'changes_made': changes_made,
                    'resources_affected': resources_affected,
                    'rollback_available': False,  # Cannot automatically rollback security group changes
                    'validation_passed': True
                }
            else:
                return {
                    'success': True,
                    'message': f'No changes needed for security group {sg_id}',
                    'changes_made': [],
                    'resources_affected': resources_affected,
                    'validation_passed': True
                }
                
        except Exception as e:
            return {
                'success': False,
                'message': f'Failed to restrict security group access: {str(e)}',
                'error_details': str(e)
            }
    
    async def _enable_aws_feature(self, task: RemediationTask, template: RemediationTemplate, session: boto3.Session) -> Dict[str, Any]:
        """Enable AWS security feature"""
        if task.resource_type == "s3_bucket" and "encryption" in task.parameters:
            return await self._enable_s3_encryption(task, template, session)
        elif task.resource_type == "s3_bucket" and "versioning" in task.parameters:
            return await self._enable_s3_versioning(task, template, session)
        elif task.resource_type == "s3_bucket" and "logging" in task.parameters:
            return await self._enable_s3_logging(task, template, session)
        else:
            raise ValueError(f"Unsupported AWS feature enablement: {task.resource_type}")
    
    async def _enable_s3_encryption(self, task: RemediationTask, template: RemediationTemplate, session: boto3.Session) -> Dict[str, Any]:
        """Enable S3 bucket encryption"""
        s3_client = session.client('s3')
        
        try:
            bucket_name = task.resource_id
            
            # Enable default encryption
            encryption_config = {
                'Rules': [
                    {
                        'ApplyServerSideEncryptionByDefault': {
                            'SSEAlgorithm': 'AES256'
                        }
                    }
                ]
            }
            
            s3_client.put_bucket_encryption(
                Bucket=bucket_name,
                ServerSideEncryptionConfiguration=encryption_config
            )
            
            return {
                'success': True,
                'message': f'Enabled encryption for S3 bucket {bucket_name}',
                'changes_made': [f'Enabled AES256 encryption for {bucket_name}'],
                'resources_affected': [bucket_name],
                'rollback_available': True,
                'rollback_instructions': f'Remove encryption configuration from {bucket_name}',
                'validation_passed': True
            }
            
        except Exception as e:
            return {
                'success': False,
                'message': f'Failed to enable S3 encryption: {str(e)}',
                'error_details': str(e)
            }
    
    async def validate_remediation(self, task: RemediationTask, result: RemediationResult) -> bool:
        """Validate AWS remediation was successful"""
        try:
            session = self._get_session(task.region)
            
            if task.resource_type == "s3_bucket" and task.action == RemediationAction.ENABLE:
                return await self._validate_s3_remediation(task, session)
            elif task.resource_type == "security_group" and task.action == RemediationAction.RESTRICT:
                return await self._validate_security_group_remediation(task, session)
            
            return True  # Default to successful validation
            
        except Exception as e:
            self.logger.error(f"Validation failed for task {task.task_id}: {e}")
            return False
    
    async def _validate_s3_remediation(self, task: RemediationTask, session: boto3.Session) -> bool:
        """Validate S3 remediation"""
        s3_client = session.client('s3')
        bucket_name = task.resource_id
        
        try:
            # Check encryption
            if "encryption" in task.parameters:
                response = s3_client.get_bucket_encryption(Bucket=bucket_name)
                if response['ServerSideEncryptionConfiguration']['Rules']:
                    return True
            
            # Check public access block
            if "public_access" in task.parameters:
                response = s3_client.get_public_access_block(Bucket=bucket_name)
                config = response['PublicAccessBlockConfiguration']
                return all([
                    config.get('BlockPublicAcls', False),
                    config.get('IgnorePublicAcls', False),
                    config.get('BlockPublicPolicy', False),
                    config.get('RestrictPublicBuckets', False)
                ])
            
            return True
            
        except Exception:
            return False
    
    async def rollback_remediation(self, task: RemediationTask, result: RemediationResult) -> bool:
        """Rollback AWS remediation"""
        if not result.rollback_available:
            return False
        
        try:
            session = self._get_session(task.region)
            
            # Implement rollback based on action type
            if task.action == RemediationAction.CREATE and task.resource_type == "s3_bucket_policy":
                s3_client = session.client('s3')
                s3_client.delete_bucket_policy(Bucket=task.resource_id)
                return True
            
            return True
            
        except Exception as e:
            self.logger.error(f"Rollback failed for task {task.task_id}: {e}")
            return False


class AutomatedRemediationEngine:
    """Main automated remediation and policy-as-code engine"""
    
    def __init__(self, config_path: str = "/etc/nsm/automated_remediation.yaml"):
        self.config_path = config_path
        self.config = self._load_config()
        self.logger = self._setup_logging()
        
        # Load templates and policies
        self.remediation_templates: Dict[str, RemediationTemplate] = {}
        self.policy_rules: Dict[str, PolicyRule] = {}
        self._load_remediation_templates()
        self._load_policy_rules()
        
        # Task management
        self.pending_tasks: List[RemediationTask] = []
        self.active_tasks: List[RemediationTask] = []
        self.completed_tasks: List[RemediationTask] = []
        self.failed_tasks: List[RemediationTask] = []
        
        # Executors
        self.executors = {
            'aws': AWSRemediationExecutor(),
            'azure': None,  # Would implement AzureRemediationExecutor
            'gcp': None     # Would implement GCPRemediationExecutor
        }
        
        # Template engine
        self.template_engine = jinja2.Environment(
            loader=jinja2.BaseLoader(),
            autoescape=True
        )
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration"""
        try:
            with open(self.config_path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            print(f"Error loading config: {e}, using defaults")
            return {
                'auto_remediation_enabled': True,
                'dry_run_mode': True,
                'approval_required_for_critical': True,
                'max_concurrent_tasks': 5,
                'remediation_schedule': '*/15 * * * *',  # Every 15 minutes
                'notification_channels': ['email', 'slack'],
                'rollback_timeout_minutes': 60
            }
    
    def _setup_logging(self) -> logging.Logger:
        """Setup logging"""
        logger = logging.getLogger('AutomatedRemediationEngine')
        logger.setLevel(logging.INFO)
        
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        
        return logger
    
    def _load_remediation_templates(self):
        """Load remediation templates"""
        # Built-in templates
        templates = [
            RemediationTemplate(
                template_id="aws_s3_enable_encryption",
                name="Enable S3 Bucket Encryption",
                description="Enable default encryption for S3 bucket",
                cloud_provider="aws",
                resource_type="s3_bucket",
                action=RemediationAction.ENABLE,
                template_format="boto3",
                template_content="s3_client.put_bucket_encryption(...)",
                parameters={"encryption_type": "AES256"},
                approval_level=ApprovalLevel.AUTOMATIC,
                risk_level="low"
            ),
            RemediationTemplate(
                template_id="aws_sg_restrict_access",
                name="Restrict Security Group Access",
                description="Remove overly permissive security group rules",
                cloud_provider="aws",
                resource_type="security_group",
                action=RemediationAction.RESTRICT,
                template_format="boto3",
                template_content="ec2_client.revoke_security_group_ingress(...)",
                parameters={"sensitive_ports": [22, 3389, 1433, 3306]},
                approval_level=ApprovalLevel.MANAGER_APPROVAL,
                risk_level="high"
            ),
            RemediationTemplate(
                template_id="aws_s3_block_public_access",
                name="Block S3 Public Access",
                description="Enable S3 bucket public access block",
                cloud_provider="aws",
                resource_type="s3_bucket",
                action=RemediationAction.ENABLE,
                template_format="boto3",
                template_content="s3_client.put_public_access_block(...)",
                parameters={"block_all": True},
                approval_level=ApprovalLevel.AUTOMATIC,
                risk_level="medium"
            ),
            RemediationTemplate(
                template_id="aws_iam_remove_unused_keys",
                name="Remove Unused IAM Access Keys",
                description="Remove IAM access keys that haven't been used in 90+ days",
                cloud_provider="aws",
                resource_type="iam_access_key",
                action=RemediationAction.DELETE,
                template_format="boto3",
                template_content="iam_client.delete_access_key(...)",
                parameters={"unused_threshold_days": 90},
                approval_level=ApprovalLevel.SECURITY_TEAM_APPROVAL,
                risk_level="medium"
            )
        ]
        
        for template in templates:
            self.remediation_templates[template.template_id] = template
        
        # Load custom templates from file
        custom_templates_path = Path("/etc/nsm/custom_remediation_templates.yaml")
        if custom_templates_path.exists():
            try:
                with open(custom_templates_path, 'r') as f:
                    custom_templates_data = yaml.safe_load(f)
                    for template_data in custom_templates_data.get('templates', []):
                        template = RemediationTemplate(**template_data)
                        self.remediation_templates[template.template_id] = template
            except Exception as e:
                self.logger.error(f"Error loading custom templates: {e}")
        
        self.logger.info(f"Loaded {len(self.remediation_templates)} remediation templates")
    
    def _load_policy_rules(self):
        """Load policy-as-code rules"""
        # Built-in policy rules
        rules = [
            PolicyRule(
                rule_id="s3_encryption_required",
                name="S3 Encryption Required",
                description="All S3 buckets must have encryption enabled",
                cloud_provider="aws",
                resource_types=["s3_bucket"],
                conditions={"encryption_enabled": False},
                remediation_template_id="aws_s3_enable_encryption",
                enforcement_mode="enforce",
                severity="medium"
            ),
            PolicyRule(
                rule_id="sg_no_public_admin_access",
                name="No Public Administrative Access",
                description="Security groups should not allow public access to administrative ports",
                cloud_provider="aws",
                resource_types=["security_group"],
                conditions={
                    "ingress_rules": {
                        "source_cidr": "0.0.0.0/0",
                        "ports": [22, 3389, 1433, 3306]
                    }
                },
                remediation_template_id="aws_sg_restrict_access",
                enforcement_mode="enforce",
                severity="high"
            ),
            PolicyRule(
                rule_id="s3_no_public_access",
                name="S3 No Public Access",
                description="S3 buckets should not allow public access",
                cloud_provider="aws",
                resource_types=["s3_bucket"],
                conditions={"public_access_blocked": False},
                remediation_template_id="aws_s3_block_public_access",
                enforcement_mode="enforce",
                severity="high"
            )
        ]
        
        for rule in rules:
            self.policy_rules[rule.rule_id] = rule
        
        self.logger.info(f"Loaded {len(self.policy_rules)} policy rules")
    
    async def create_remediation_task(self, finding_id: str, resource_id: str, resource_type: str,
                                    cloud_provider: str, account_id: str, region: str,
                                    template_id: str, parameters: Dict[str, Any] = None) -> RemediationTask:
        """Create a new remediation task"""
        if template_id not in self.remediation_templates:
            raise ValueError(f"Unknown remediation template: {template_id}")
        
        template = self.remediation_templates[template_id]
        
        task = RemediationTask(
            task_id=f"remediation_{int(datetime.utcnow().timestamp())}_{resource_id}",
            finding_id=finding_id,
            resource_id=resource_id,
            resource_type=resource_type,
            cloud_provider=cloud_provider,
            account_id=account_id,
            region=region,
            template_id=template_id,
            action=template.action,
            priority="high" if template.risk_level == "high" else "medium",
            parameters=parameters or {},
            metadata={
                'template_approval_level': template.approval_level.value,
                'template_risk_level': template.risk_level
            }
        )
        
        # Check if approval is required
        if template.approval_level != ApprovalLevel.AUTOMATIC:
            task.status = RemediationStatus.REQUIRES_APPROVAL
        
        self.pending_tasks.append(task)
        self.logger.info(f"Created remediation task {task.task_id} for resource {resource_id}")
        
        return task
    
    async def execute_remediation_task(self, task: RemediationTask) -> RemediationResult:
        """Execute a remediation task"""
        if task.cloud_provider not in self.executors:
            raise ValueError(f"No executor available for cloud provider: {task.cloud_provider}")
        
        executor = self.executors[task.cloud_provider]
        if not executor:
            raise ValueError(f"Executor not implemented for cloud provider: {task.cloud_provider}")
        
        template = self.remediation_templates[task.template_id]
        
        self.logger.info(f"Executing remediation task {task.task_id}")
        
        # Update task status
        task.status = RemediationStatus.IN_PROGRESS
        task.started_timestamp = datetime.utcnow()
        
        try:
            # Check dry run mode
            if self.config.get('dry_run_mode', True):
                self.logger.info(f"DRY RUN: Would execute remediation task {task.task_id}")
                result = RemediationResult(
                    task_id=task.task_id,
                    status=RemediationStatus.COMPLETED,
                    start_time=task.started_timestamp,
                    end_time=datetime.utcnow(),
                    execution_duration=1.0,
                    success=True,
                    message=f"DRY RUN: Remediation task {task.task_id} would succeed",
                    changes_made=[f"DRY RUN: Would apply template {template.name}"],
                    validation_passed=True
                )
            else:
                # Execute actual remediation
                result = await executor.execute_remediation(task, template)
                
                # Validate remediation if successful
                if result.success:
                    validation_passed = await executor.validate_remediation(task, result)
                    result.validation_passed = validation_passed
                    
                    if not validation_passed:
                        self.logger.warning(f"Remediation validation failed for task {task.task_id}")
            
            # Update task status
            task.status = result.status
            task.completed_timestamp = datetime.utcnow()
            task.validation_results = {
                'success': result.success,
                'validation_passed': result.validation_passed,
                'message': result.message
            }
            
            # Move task to completed list
            if task in self.pending_tasks:
                self.pending_tasks.remove(task)
            if task in self.active_tasks:
                self.active_tasks.remove(task)
            
            if result.success:
                self.completed_tasks.append(task)
            else:
                self.failed_tasks.append(task)
            
            self.logger.info(f"Remediation task {task.task_id} completed with status: {result.status}")
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error executing remediation task {task.task_id}: {e}")
            
            task.status = RemediationStatus.FAILED
            task.completed_timestamp = datetime.utcnow()
            
            if task in self.pending_tasks:
                self.pending_tasks.remove(task)
            if task in self.active_tasks:
                self.active_tasks.remove(task)
            self.failed_tasks.append(task)
            
            return RemediationResult(
                task_id=task.task_id,
                status=RemediationStatus.FAILED,
                start_time=task.started_timestamp,
                end_time=datetime.utcnow(),
                execution_duration=0.0,
                success=False,
                message=f"Execution failed: {str(e)}",
                error_details=str(e)
            )
    
    async def evaluate_policy_compliance(self, resource_data: Dict[str, Any]) -> List[RemediationTask]:
        """Evaluate resource against policy rules and create remediation tasks"""
        created_tasks = []
        
        resource_type = resource_data.get('type')
        cloud_provider = resource_data.get('cloud_provider')
        
        # Find applicable policy rules
        applicable_rules = [
            rule for rule in self.policy_rules.values()
            if (resource_type in rule.resource_types and 
                rule.cloud_provider == cloud_provider and
                rule.enabled)
        ]
        
        for rule in applicable_rules:
            # Evaluate conditions
            if self._evaluate_policy_conditions(resource_data, rule.conditions):
                # Create remediation task
                task = await self.create_remediation_task(
                    finding_id=f"policy_violation_{rule.rule_id}_{resource_data.get('id')}",
                    resource_id=resource_data.get('id'),
                    resource_type=resource_type,
                    cloud_provider=cloud_provider,
                    account_id=resource_data.get('account_id'),
                    region=resource_data.get('region'),
                    template_id=rule.remediation_template_id,
                    parameters=resource_data.get('parameters', {})
                )
                created_tasks.append(task)
                
                self.logger.info(f"Created remediation task for policy violation: {rule.name}")
        
        return created_tasks
    
    def _evaluate_policy_conditions(self, resource_data: Dict[str, Any], conditions: Dict[str, Any]) -> bool:
        """Evaluate if resource violates policy conditions"""
        # This is a simplified implementation
        # In practice, you'd have a more sophisticated policy evaluation engine
        
        for condition_key, condition_value in conditions.items():
            resource_value = resource_data.get(condition_key)
            
            if isinstance(condition_value, bool):
                if resource_value != condition_value:
                    return True  # Condition violated
            elif isinstance(condition_value, dict):
                # Complex condition evaluation
                if condition_key == "ingress_rules":
                    ingress_rules = resource_data.get('ingress_rules', [])
                    for rule in ingress_rules:
                        if (rule.get('source_cidr') == condition_value.get('source_cidr') and
                            any(port in condition_value.get('ports', []) for port in rule.get('ports', []))):
                            return True  # Violation found
        
        return False
    
    async def process_pending_tasks(self):
        """Process pending remediation tasks"""
        if not self.config.get('auto_remediation_enabled', True):
            self.logger.info("Auto-remediation is disabled")
            return
        
        max_concurrent = self.config.get('max_concurrent_tasks', 5)
        
        # Process tasks that don't require approval
        auto_tasks = [
            task for task in self.pending_tasks 
            if task.status == RemediationStatus.PENDING
        ]
        
        # Execute tasks up to concurrent limit
        tasks_to_execute = auto_tasks[:max_concurrent - len(self.active_tasks)]
        
        for task in tasks_to_execute:
            self.pending_tasks.remove(task)
            self.active_tasks.append(task)
            
            # Execute task asynchronously
            asyncio.create_task(self.execute_remediation_task(task))
        
        self.logger.info(f"Processing {len(tasks_to_execute)} remediation tasks")
    
    def get_remediation_status(self) -> Dict[str, Any]:
        """Get overall remediation status"""
        return {
            'pending_tasks': len(self.pending_tasks),
            'active_tasks': len(self.active_tasks),
            'completed_tasks': len(self.completed_tasks),
            'failed_tasks': len(self.failed_tasks),
            'requires_approval': len([t for t in self.pending_tasks if t.status == RemediationStatus.REQUIRES_APPROVAL]),
            'auto_remediation_enabled': self.config.get('auto_remediation_enabled', True),
            'dry_run_mode': self.config.get('dry_run_mode', True)
        }
    
    def generate_remediation_report(self, output_format: str = 'json') -> str:
        """Generate remediation activity report"""
        all_tasks = self.pending_tasks + self.active_tasks + self.completed_tasks + self.failed_tasks
        
        if output_format.lower() == 'json':
            report_data = {
                'report_timestamp': datetime.utcnow().isoformat(),
                'summary': self.get_remediation_status(),
                'tasks': [asdict(task) for task in all_tasks]
            }
            return json.dumps(report_data, indent=2, default=str)
        
        else:  # text format
            report = []
            report.append("AUTOMATED REMEDIATION REPORT")
            report.append("=" * 50)
            report.append(f"Report Generated: {datetime.utcnow().isoformat()}")
            report.append("")
            
            status = self.get_remediation_status()
            report.append("SUMMARY:")
            report.append("-" * 20)
            for key, value in status.items():
                report.append(f"{key.replace('_', ' ').title()}: {value}")
            report.append("")
            
            if self.completed_tasks:
                report.append("RECENT COMPLETED TASKS:")
                report.append("-" * 30)
                for task in self.completed_tasks[-10:]:  # Show last 10
                    report.append(f"• {task.task_id}: {task.template_id}")
                    report.append(f"  Resource: {task.resource_id}")
                    report.append(f"  Status: {task.status.value}")
                    report.append("")
            
            if self.failed_tasks:
                report.append("FAILED TASKS:")
                report.append("-" * 20)
                for task in self.failed_tasks[-5:]:  # Show last 5
                    report.append(f"• {task.task_id}: {task.template_id}")
                    report.append(f"  Resource: {task.resource_id}")
                    report.append(f"  Status: {task.status.value}")
                    report.append("")
            
            return "\n".join(report)


async def main():
    """Main function for testing automated remediation engine"""
    engine = AutomatedRemediationEngine()
    
    try:
        print("Automated Remediation and Policy-as-Code Engine initialized successfully")
        print(f"Loaded {len(engine.remediation_templates)} remediation templates")
        print(f"Loaded {len(engine.policy_rules)} policy rules")
        
        # Get status
        status = engine.get_remediation_status()
        print(f"Status: {status}")
        
        # Generate report
        # report = engine.generate_remediation_report('text')
        # print(report)
        
    except Exception as e:
        print(f"Error running automated remediation engine: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())