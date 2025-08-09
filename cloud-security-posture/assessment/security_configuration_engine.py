#!/usr/bin/env python3
"""
iSECTECH Cloud Security Posture Management - Security Configuration Assessment Engine
Comprehensive security configuration assessment with CIS benchmarks and custom policies
"""

import asyncio
import json
import logging
import yaml
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Any, Union, Set
from abc import ABC, abstractmethod

import boto3
from azure.identity import DefaultAzureCredential
from azure.mgmt.resource import ResourceManagementClient
from google.cloud import asset_v1
from google.oauth2 import service_account


class Severity(Enum):
    """Security finding severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ComplianceFramework(Enum):
    """Supported compliance frameworks"""
    CIS_AWS_FOUNDATIONS = "cis_aws_foundations_1.4"
    CIS_AZURE_FOUNDATIONS = "cis_azure_foundations_1.3"
    CIS_GCP_FOUNDATIONS = "cis_gcp_foundations_1.3"
    NIST_CSF = "nist_cybersecurity_framework"
    SOC2_TYPE2 = "soc2_type2"
    PCI_DSS = "pci_dss_3.2.1"
    HIPAA = "hipaa"
    GDPR = "gdpr"
    CUSTOM = "custom"


@dataclass
class SecurityRule:
    """Security assessment rule definition"""
    rule_id: str
    title: str
    description: str
    severity: Severity
    compliance_frameworks: List[ComplianceFramework]
    cloud_provider: str  # aws, azure, gcp, multi
    resource_types: List[str]
    check_function: str  # Name of the function to execute
    remediation_guidance: str
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    enabled: bool = True


@dataclass
class SecurityFinding:
    """Security configuration finding"""
    finding_id: str
    rule_id: str
    resource_id: str
    resource_type: str
    cloud_provider: str
    region: str
    account_id: str
    severity: Severity
    title: str
    description: str
    current_value: Any
    expected_value: Any
    remediation_guidance: str
    compliance_frameworks: List[ComplianceFramework]
    timestamp: datetime
    raw_resource_data: Dict[str, Any] = field(default_factory=dict)
    tags: Dict[str, str] = field(default_factory=dict)


@dataclass
class AssessmentResult:
    """Complete assessment result"""
    assessment_id: str
    timestamp: datetime
    cloud_provider: str
    account_id: str
    region: str
    total_resources_assessed: int
    total_findings: int
    findings_by_severity: Dict[Severity, int]
    compliance_score: float  # Percentage
    findings: List[SecurityFinding]
    execution_time_seconds: float
    metadata: Dict[str, Any] = field(default_factory=dict)


class SecurityAssessmentRule(ABC):
    """Base class for security assessment rules"""
    
    def __init__(self, rule: SecurityRule):
        self.rule = rule
        self.logger = logging.getLogger(f"{self.__class__.__name__}.{rule.rule_id}")
    
    @abstractmethod
    async def assess(self, resource: Dict[str, Any], context: Dict[str, Any]) -> Optional[SecurityFinding]:
        """Assess a resource against this rule"""
        pass
    
    def create_finding(self, resource: Dict[str, Any], context: Dict[str, Any], 
                      current_value: Any, expected_value: Any) -> SecurityFinding:
        """Create a security finding"""
        return SecurityFinding(
            finding_id=f"{self.rule.rule_id}_{resource.get('id', 'unknown')}_{int(datetime.utcnow().timestamp())}",
            rule_id=self.rule.rule_id,
            resource_id=resource.get('id', 'unknown'),
            resource_type=resource.get('type', 'unknown'),
            cloud_provider=context.get('cloud_provider', 'unknown'),
            region=context.get('region', 'unknown'),
            account_id=context.get('account_id', 'unknown'),
            severity=self.rule.severity,
            title=self.rule.title,
            description=self.rule.description,
            current_value=current_value,
            expected_value=expected_value,
            remediation_guidance=self.rule.remediation_guidance,
            compliance_frameworks=self.rule.compliance_frameworks,
            timestamp=datetime.utcnow(),
            raw_resource_data=resource,
            tags=context.get('tags', {})
        )


class CISAWSRules:
    """CIS AWS Foundations Benchmark rules"""
    
    @staticmethod
    def get_rules() -> List[SecurityRule]:
        return [
            SecurityRule(
                rule_id="cis_aws_1.3",
                title="Ensure credentials unused for 90 days or greater are disabled",
                description="AWS IAM users can access AWS resources using different types of credentials, such as passwords or access keys. It is recommended that all credentials that have been unused in 90 or greater days be deactivated or removed.",
                severity=Severity.MEDIUM,
                compliance_frameworks=[ComplianceFramework.CIS_AWS_FOUNDATIONS],
                cloud_provider="aws",
                resource_types=["iam_user"],
                check_function="check_unused_credentials",
                remediation_guidance="Review and disable unused credentials through AWS IAM console or CLI",
                references=["https://d1.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf"],
                tags=["iam", "credentials", "access_management"]
            ),
            SecurityRule(
                rule_id="cis_aws_1.4",
                title="Ensure access keys are rotated every 90 days",
                description="Access keys consist of an access key ID and secret access key, which are used to sign programmatic requests to AWS. AWS users need their own access keys to make programmatic calls to AWS from the AWS Command Line Interface (CLI), Tools for Windows PowerShell, the AWS SDKs, or direct HTTP calls using the APIs for individual AWS services.",
                severity=Severity.MEDIUM,
                compliance_frameworks=[ComplianceFramework.CIS_AWS_FOUNDATIONS],
                cloud_provider="aws",
                resource_types=["iam_access_key"],
                check_function="check_access_key_rotation",
                remediation_guidance="Rotate access keys every 90 days through AWS IAM console or CLI",
                references=["https://d1.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf"],
                tags=["iam", "access_keys", "rotation"]
            ),
            SecurityRule(
                rule_id="cis_aws_2.1.1",
                title="Ensure S3 bucket access logging is enabled",
                description="S3 Bucket access logging generates a log that contains access records for each request made to your S3 bucket. An access log record contains details about the request, such as the request type, the resources specified in the request worked, and the time and date the request was processed.",
                severity=Severity.LOW,
                compliance_frameworks=[ComplianceFramework.CIS_AWS_FOUNDATIONS],
                cloud_provider="aws",
                resource_types=["s3_bucket"],
                check_function="check_s3_access_logging",
                remediation_guidance="Enable S3 bucket access logging through AWS S3 console or CLI",
                references=["https://d1.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf"],
                tags=["s3", "logging", "access_logs"]
            ),
            SecurityRule(
                rule_id="cis_aws_2.1.3",
                title="Ensure S3 bucket public access block is enabled",
                description="Amazon S3 provides Block Public Access (BPA) settings for buckets and accounts to help you manage public access to Amazon S3 resources. By default, S3 buckets and objects are created with public access disabled. However, an IAM principal with sufficient S3 permissions can enable public access as a configuration option.",
                severity=Severity.HIGH,
                compliance_frameworks=[ComplianceFramework.CIS_AWS_FOUNDATIONS],
                cloud_provider="aws",
                resource_types=["s3_bucket"],
                check_function="check_s3_public_access_block",
                remediation_guidance="Enable S3 bucket public access block through AWS S3 console or CLI",
                references=["https://d1.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf"],
                tags=["s3", "public_access", "security"]
            ),
            SecurityRule(
                rule_id="cis_aws_4.1",
                title="Ensure no security groups allow ingress from 0.0.0.0/0 to port 22",
                description="Security groups provide stateful filtering of ingress/egress network traffic to AWS resources. It is recommended that no security group allows unrestricted ingress access to port 22.",
                severity=Severity.HIGH,
                compliance_frameworks=[ComplianceFramework.CIS_AWS_FOUNDATIONS],
                cloud_provider="aws",
                resource_types=["security_group"],
                check_function="check_security_group_ssh_access",
                remediation_guidance="Remove or restrict ingress rules allowing access from 0.0.0.0/0 to port 22",
                references=["https://d1.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf"],
                tags=["security_groups", "ssh", "network_security"]
            )
        ]


class CISAzureRules:
    """CIS Azure Foundations Benchmark rules"""
    
    @staticmethod
    def get_rules() -> List[SecurityRule]:
        return [
            SecurityRule(
                rule_id="cis_azure_1.1",
                title="Ensure that multi-factor authentication is enabled for all privileged users",
                description="Multi-factor authentication requires an individual to present a minimum of two separate forms of authentication before access is granted. Multi-factor authentication provides additional assurance that the individual attempting to gain access is who they claim to be.",
                severity=Severity.HIGH,
                compliance_frameworks=[ComplianceFramework.CIS_AZURE_FOUNDATIONS],
                cloud_provider="azure",
                resource_types=["azure_ad_user"],
                check_function="check_azure_mfa_privileged_users",
                remediation_guidance="Enable MFA for all privileged users through Azure AD portal",
                references=["https://www.cisecurity.org/benchmark/azure"],
                tags=["azure_ad", "mfa", "privileged_access"]
            ),
            SecurityRule(
                rule_id="cis_azure_2.1.1",
                title="Ensure that 'Secure transfer required' is set to 'Enabled'",
                description="The secure transfer option enhances the security of a storage account by only allowing requests to the storage account by a secure connection. For example, when calling REST APIs to access storage accounts, the connection must use HTTPS.",
                severity=Severity.MEDIUM,
                compliance_frameworks=[ComplianceFramework.CIS_AZURE_FOUNDATIONS],
                cloud_provider="azure",
                resource_types=["storage_account"],
                check_function="check_azure_storage_secure_transfer",
                remediation_guidance="Enable 'Secure transfer required' for storage accounts through Azure portal or CLI",
                references=["https://www.cisecurity.org/benchmark/azure"],
                tags=["storage", "https", "secure_transfer"]
            ),
            SecurityRule(
                rule_id="cis_azure_6.1",
                title="Ensure that RDP access is restricted from the internet",
                description="Network security groups should be configured to restrict RDP access from the internet. Public accessibility to remote desktop services (RDP) on port 3389 can provide a potential attack surface for attackers to gain access to Azure resources.",
                severity=Severity.HIGH,
                compliance_frameworks=[ComplianceFramework.CIS_AZURE_FOUNDATIONS],
                cloud_provider="azure",
                resource_types=["network_security_group"],
                check_function="check_azure_rdp_access_restriction",
                remediation_guidance="Restrict RDP access from internet through Azure network security groups",
                references=["https://www.cisecurity.org/benchmark/azure"],
                tags=["network_security", "rdp", "internet_access"]
            )
        ]


class CISGCPRules:
    """CIS GCP Foundations Benchmark rules"""
    
    @staticmethod
    def get_rules() -> List[SecurityRule]:
        return [
            SecurityRule(
                rule_id="cis_gcp_1.4",
                title="Ensure that there are only GCP-managed service account keys for each service account",
                description="User managed service account keys are rotated only if you initiate the rotation. Automatically rotating keys reduces the risk of compromise.",
                severity=Severity.MEDIUM,
                compliance_frameworks=[ComplianceFramework.CIS_GCP_FOUNDATIONS],
                cloud_provider="gcp",
                resource_types=["service_account"],
                check_function="check_gcp_service_account_keys",
                remediation_guidance="Remove user-managed service account keys and use GCP-managed keys",
                references=["https://www.cisecurity.org/benchmark/google_cloud_computing_platform"],
                tags=["service_accounts", "key_management", "gcp_managed"]
            ),
            SecurityRule(
                rule_id="cis_gcp_3.3",
                title="Ensure that Cloud Storage bucket is not anonymously or publicly accessible",
                description="It is recommended that IAM policy on Cloud Storage bucket does not allows anonymous or public access.",
                severity=Severity.HIGH,
                compliance_frameworks=[ComplianceFramework.CIS_GCP_FOUNDATIONS],
                cloud_provider="gcp",
                resource_types=["storage_bucket"],
                check_function="check_gcp_storage_public_access",
                remediation_guidance="Remove public access from Cloud Storage bucket IAM policies",
                references=["https://www.cisecurity.org/benchmark/google_cloud_computing_platform"],
                tags=["cloud_storage", "public_access", "iam"]
            ),
            SecurityRule(
                rule_id="cis_gcp_3.6",
                title="Ensure that Cloud SQL database instances are not open to the world",
                description="Database Server should accept connections only from trusted Network(s)/IP(s) and restrict access from the world.",
                severity=Severity.HIGH,
                compliance_frameworks=[ComplianceFramework.CIS_GCP_FOUNDATIONS],
                cloud_provider="gcp",
                resource_types=["sql_instance"],
                check_function="check_gcp_sql_public_access",
                remediation_guidance="Restrict Cloud SQL instance access to specific networks/IPs",
                references=["https://www.cisecurity.org/benchmark/google_cloud_computing_platform"],
                tags=["cloud_sql", "network_access", "database_security"]
            )
        ]


class SecurityConfigurationAssessmentEngine:
    """Main security configuration assessment engine"""
    
    def __init__(self, config_path: str = "/etc/nsm/cloud_security_posture.yaml"):
        self.config_path = config_path
        self.config = self._load_config()
        self.logger = self._setup_logging()
        
        # Load all rules
        self.rules: Dict[str, SecurityRule] = {}
        self._load_all_rules()
        
        # Assessment rule implementations
        self.rule_implementations: Dict[str, SecurityAssessmentRule] = {}
        self._initialize_rule_implementations()
        
        # Results storage
        self.assessment_results: List[AssessmentResult] = []
        
        # Cloud clients (initialized on demand)
        self._aws_clients = {}
        self._azure_clients = {}
        self._gcp_clients = {}
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration"""
        try:
            with open(self.config_path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            print(f"Error loading config: {e}, using defaults")
            return {
                'enabled_frameworks': ['cis_aws_foundations_1.4', 'cis_azure_foundations_1.3', 'cis_gcp_foundations_1.3'],
                'cloud_providers': ['aws', 'azure', 'gcp'],
                'assessment_schedule': '0 2 * * *',  # Daily at 2 AM
                'parallel_assessments': 10,
                'finding_retention_days': 90
            }
    
    def _setup_logging(self) -> logging.Logger:
        """Setup logging"""
        logger = logging.getLogger('SecurityConfigurationAssessmentEngine')
        logger.setLevel(logging.INFO)
        
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        
        return logger
    
    def _load_all_rules(self):
        """Load all security rules"""
        # Load CIS rules
        for rule in CISAWSRules.get_rules():
            self.rules[rule.rule_id] = rule
        
        for rule in CISAzureRules.get_rules():
            self.rules[rule.rule_id] = rule
        
        for rule in CISGCPRules.get_rules():
            self.rules[rule.rule_id] = rule
        
        # Load custom rules from file if exists
        custom_rules_path = Path("/etc/nsm/custom_security_rules.yaml")
        if custom_rules_path.exists():
            try:
                with open(custom_rules_path, 'r') as f:
                    custom_rules_data = yaml.safe_load(f)
                    for rule_data in custom_rules_data.get('rules', []):
                        rule = SecurityRule(**rule_data)
                        self.rules[rule.rule_id] = rule
            except Exception as e:
                self.logger.error(f"Error loading custom rules: {e}")
        
        self.logger.info(f"Loaded {len(self.rules)} security rules")
    
    def _initialize_rule_implementations(self):
        """Initialize rule implementation classes"""
        # This would be expanded with actual rule implementations
        # For now, we'll create a generic implementation factory
        pass
    
    async def assess_aws_account(self, account_id: str, regions: List[str] = None) -> AssessmentResult:
        """Assess AWS account security configuration"""
        if regions is None:
            regions = ['us-east-1', 'us-west-2', 'eu-west-1']
        
        start_time = datetime.utcnow()
        all_findings = []
        total_resources = 0
        
        self.logger.info(f"Starting AWS assessment for account {account_id}")
        
        for region in regions:
            try:
                # Initialize AWS clients for region
                session = boto3.Session(region_name=region)
                
                context = {
                    'cloud_provider': 'aws',
                    'account_id': account_id,
                    'region': region,
                    'session': session
                }
                
                # Assess different resource types
                region_findings = []
                
                # IAM resources (global, only assess once)
                if region == regions[0]:
                    iam_findings = await self._assess_aws_iam_resources(context)
                    region_findings.extend(iam_findings)
                
                # S3 buckets (global, only assess once)
                if region == regions[0]:
                    s3_findings = await self._assess_aws_s3_resources(context)
                    region_findings.extend(s3_findings)
                
                # EC2 security groups
                sg_findings = await self._assess_aws_security_groups(context)
                region_findings.extend(sg_findings)
                
                # Add more resource type assessments here
                
                all_findings.extend(region_findings)
                total_resources += len(region_findings)
                
                self.logger.info(f"Assessed {len(region_findings)} resources in region {region}")
                
            except Exception as e:
                self.logger.error(f"Error assessing AWS region {region}: {e}")
        
        # Calculate summary metrics
        findings_by_severity = {}
        for severity in Severity:
            findings_by_severity[severity] = len([f for f in all_findings if f.severity == severity])
        
        # Calculate compliance score (percentage of resources without critical/high findings)
        critical_high_findings = len([f for f in all_findings if f.severity in [Severity.CRITICAL, Severity.HIGH]])
        compliance_score = max(0, (total_resources - critical_high_findings) / total_resources * 100) if total_resources > 0 else 100
        
        end_time = datetime.utcnow()
        execution_time = (end_time - start_time).total_seconds()
        
        result = AssessmentResult(
            assessment_id=f"aws_{account_id}_{int(start_time.timestamp())}",
            timestamp=start_time,
            cloud_provider="aws",
            account_id=account_id,
            region="multi-region",
            total_resources_assessed=total_resources,
            total_findings=len(all_findings),
            findings_by_severity=findings_by_severity,
            compliance_score=compliance_score,
            findings=all_findings,
            execution_time_seconds=execution_time,
            metadata={'regions_assessed': regions}
        )
        
        self.assessment_results.append(result)
        self.logger.info(f"AWS assessment completed: {len(all_findings)} findings, {compliance_score:.1f}% compliance score")
        
        return result
    
    async def _assess_aws_iam_resources(self, context: Dict[str, Any]) -> List[SecurityFinding]:
        """Assess AWS IAM resources"""
        findings = []
        session = context['session']
        iam_client = session.client('iam')
        
        try:
            # Get all IAM users
            paginator = iam_client.get_paginator('list_users')
            for page in paginator.paginate():
                for user in page['Users']:
                    # Check for unused credentials (CIS 1.3)
                    user_finding = await self._check_aws_unused_credentials(user, context)
                    if user_finding:
                        findings.append(user_finding)
                    
                    # Check access key rotation (CIS 1.4)
                    access_keys = iam_client.list_access_keys(UserName=user['UserName'])
                    for key in access_keys['AccessKeyMetadata']:
                        key_finding = await self._check_aws_access_key_rotation(key, user, context)
                        if key_finding:
                            findings.append(key_finding)
        
        except Exception as e:
            self.logger.error(f"Error assessing AWS IAM resources: {e}")
        
        return findings
    
    async def _assess_aws_s3_resources(self, context: Dict[str, Any]) -> List[SecurityFinding]:
        """Assess AWS S3 resources"""
        findings = []
        session = context['session']
        s3_client = session.client('s3')
        
        try:
            # Get all S3 buckets
            response = s3_client.list_buckets()
            for bucket in response['Buckets']:
                bucket_name = bucket['Name']
                
                # Check S3 access logging (CIS 2.1.1)
                logging_finding = await self._check_aws_s3_access_logging(bucket_name, context)
                if logging_finding:
                    findings.append(logging_finding)
                
                # Check S3 public access block (CIS 2.1.3)
                public_access_finding = await self._check_aws_s3_public_access_block(bucket_name, context)
                if public_access_finding:
                    findings.append(public_access_finding)
        
        except Exception as e:
            self.logger.error(f"Error assessing AWS S3 resources: {e}")
        
        return findings
    
    async def _assess_aws_security_groups(self, context: Dict[str, Any]) -> List[SecurityFinding]:
        """Assess AWS Security Groups"""
        findings = []
        session = context['session']
        ec2_client = session.client('ec2')
        
        try:
            # Get all security groups
            paginator = ec2_client.get_paginator('describe_security_groups')
            for page in paginator.paginate():
                for sg in page['SecurityGroups']:
                    # Check for SSH access from 0.0.0.0/0 (CIS 4.1)
                    ssh_finding = await self._check_aws_security_group_ssh_access(sg, context)
                    if ssh_finding:
                        findings.append(ssh_finding)
        
        except Exception as e:
            self.logger.error(f"Error assessing AWS Security Groups: {e}")
        
        return findings
    
    async def _check_aws_unused_credentials(self, user: Dict[str, Any], context: Dict[str, Any]) -> Optional[SecurityFinding]:
        """Check for unused AWS credentials (CIS 1.3)"""
        try:
            last_used = user.get('PasswordLastUsed')
            if last_used:
                days_since_used = (datetime.utcnow().replace(tzinfo=None) - last_used.replace(tzinfo=None)).days
                if days_since_used > 90:
                    rule = self.rules.get('cis_aws_1.3')
                    if rule:
                        return SecurityFinding(
                            finding_id=f"cis_aws_1.3_{user['UserName']}_{int(datetime.utcnow().timestamp())}",
                            rule_id=rule.rule_id,
                            resource_id=user['UserName'],
                            resource_type="iam_user",
                            cloud_provider=context['cloud_provider'],
                            region=context['region'],
                            account_id=context['account_id'],
                            severity=rule.severity,
                            title=rule.title,
                            description=f"User {user['UserName']} has not used credentials for {days_since_used} days",
                            current_value=f"{days_since_used} days",
                            expected_value="<= 90 days",
                            remediation_guidance=rule.remediation_guidance,
                            compliance_frameworks=rule.compliance_frameworks,
                            timestamp=datetime.utcnow(),
                            raw_resource_data=user
                        )
        except Exception as e:
            self.logger.error(f"Error checking unused credentials for user {user.get('UserName')}: {e}")
        
        return None
    
    async def _check_aws_access_key_rotation(self, key: Dict[str, Any], user: Dict[str, Any], 
                                           context: Dict[str, Any]) -> Optional[SecurityFinding]:
        """Check AWS access key rotation (CIS 1.4)"""
        try:
            created_date = key.get('CreateDate')
            if created_date:
                days_since_created = (datetime.utcnow().replace(tzinfo=None) - created_date.replace(tzinfo=None)).days
                if days_since_created > 90:
                    rule = self.rules.get('cis_aws_1.4')
                    if rule:
                        return SecurityFinding(
                            finding_id=f"cis_aws_1.4_{key['AccessKeyId']}_{int(datetime.utcnow().timestamp())}",
                            rule_id=rule.rule_id,
                            resource_id=key['AccessKeyId'],
                            resource_type="iam_access_key",
                            cloud_provider=context['cloud_provider'],
                            region=context['region'],
                            account_id=context['account_id'],
                            severity=rule.severity,
                            title=rule.title,
                            description=f"Access key {key['AccessKeyId']} for user {user['UserName']} is {days_since_created} days old",
                            current_value=f"{days_since_created} days",
                            expected_value="<= 90 days",
                            remediation_guidance=rule.remediation_guidance,
                            compliance_frameworks=rule.compliance_frameworks,
                            timestamp=datetime.utcnow(),
                            raw_resource_data=key
                        )
        except Exception as e:
            self.logger.error(f"Error checking access key rotation for key {key.get('AccessKeyId')}: {e}")
        
        return None
    
    async def _check_aws_s3_access_logging(self, bucket_name: str, context: Dict[str, Any]) -> Optional[SecurityFinding]:
        """Check S3 bucket access logging (CIS 2.1.1)"""
        try:
            session = context['session']
            s3_client = session.client('s3')
            
            try:
                response = s3_client.get_bucket_logging(Bucket=bucket_name)
                logging_enabled = 'LoggingEnabled' in response
            except s3_client.exceptions.NoSuchBucket:
                return None
            except Exception:
                logging_enabled = False
            
            if not logging_enabled:
                rule = self.rules.get('cis_aws_2.1.1')
                if rule:
                    return SecurityFinding(
                        finding_id=f"cis_aws_2.1.1_{bucket_name}_{int(datetime.utcnow().timestamp())}",
                        rule_id=rule.rule_id,
                        resource_id=bucket_name,
                        resource_type="s3_bucket",
                        cloud_provider=context['cloud_provider'],
                        region=context['region'],
                        account_id=context['account_id'],
                        severity=rule.severity,
                        title=rule.title,
                        description=f"S3 bucket {bucket_name} does not have access logging enabled",
                        current_value="Disabled",
                        expected_value="Enabled",
                        remediation_guidance=rule.remediation_guidance,
                        compliance_frameworks=rule.compliance_frameworks,
                        timestamp=datetime.utcnow(),
                        raw_resource_data={'bucket_name': bucket_name}
                    )
        except Exception as e:
            self.logger.error(f"Error checking S3 access logging for bucket {bucket_name}: {e}")
        
        return None
    
    async def _check_aws_s3_public_access_block(self, bucket_name: str, context: Dict[str, Any]) -> Optional[SecurityFinding]:
        """Check S3 bucket public access block (CIS 2.1.3)"""
        try:
            session = context['session']
            s3_client = session.client('s3')
            
            try:
                response = s3_client.get_public_access_block(Bucket=bucket_name)
                config = response.get('PublicAccessBlockConfiguration', {})
                
                all_blocked = all([
                    config.get('BlockPublicAcls', False),
                    config.get('IgnorePublicAcls', False),
                    config.get('BlockPublicPolicy', False),
                    config.get('RestrictPublicBuckets', False)
                ])
            except s3_client.exceptions.NoSuchPublicAccessBlockConfiguration:
                all_blocked = False
            except Exception:
                all_blocked = False
            
            if not all_blocked:
                rule = self.rules.get('cis_aws_2.1.3')
                if rule:
                    return SecurityFinding(
                        finding_id=f"cis_aws_2.1.3_{bucket_name}_{int(datetime.utcnow().timestamp())}",
                        rule_id=rule.rule_id,
                        resource_id=bucket_name,
                        resource_type="s3_bucket",
                        cloud_provider=context['cloud_provider'],
                        region=context['region'],
                        account_id=context['account_id'],
                        severity=rule.severity,
                        title=rule.title,
                        description=f"S3 bucket {bucket_name} does not have all public access blocked",
                        current_value="Not fully blocked",
                        expected_value="All public access blocked",
                        remediation_guidance=rule.remediation_guidance,
                        compliance_frameworks=rule.compliance_frameworks,
                        timestamp=datetime.utcnow(),
                        raw_resource_data={'bucket_name': bucket_name, 'config': config if 'config' in locals() else {}}
                    )
        except Exception as e:
            self.logger.error(f"Error checking S3 public access block for bucket {bucket_name}: {e}")
        
        return None
    
    async def _check_aws_security_group_ssh_access(self, sg: Dict[str, Any], context: Dict[str, Any]) -> Optional[SecurityFinding]:
        """Check security group SSH access (CIS 4.1)"""
        try:
            for rule in sg.get('IpPermissions', []):
                if rule.get('FromPort') == 22 and rule.get('ToPort') == 22:
                    for ip_range in rule.get('IpRanges', []):
                        if ip_range.get('CidrIp') == '0.0.0.0/0':
                            rule_def = self.rules.get('cis_aws_4.1')
                            if rule_def:
                                return SecurityFinding(
                                    finding_id=f"cis_aws_4.1_{sg['GroupId']}_{int(datetime.utcnow().timestamp())}",
                                    rule_id=rule_def.rule_id,
                                    resource_id=sg['GroupId'],
                                    resource_type="security_group",
                                    cloud_provider=context['cloud_provider'],
                                    region=context['region'],
                                    account_id=context['account_id'],
                                    severity=rule_def.severity,
                                    title=rule_def.title,
                                    description=f"Security group {sg['GroupId']} allows SSH access from 0.0.0.0/0",
                                    current_value="0.0.0.0/0",
                                    expected_value="Restricted IP ranges",
                                    remediation_guidance=rule_def.remediation_guidance,
                                    compliance_frameworks=rule_def.compliance_frameworks,
                                    timestamp=datetime.utcnow(),
                                    raw_resource_data=sg
                                )
        except Exception as e:
            self.logger.error(f"Error checking security group SSH access for {sg.get('GroupId')}: {e}")
        
        return None
    
    async def assess_azure_subscription(self, subscription_id: str) -> AssessmentResult:
        """Assess Azure subscription security configuration"""
        start_time = datetime.utcnow()
        all_findings = []
        total_resources = 0
        
        self.logger.info(f"Starting Azure assessment for subscription {subscription_id}")
        
        try:
            # Initialize Azure clients
            credential = DefaultAzureCredential()
            
            context = {
                'cloud_provider': 'azure',
                'account_id': subscription_id,
                'region': 'global',
                'credential': credential
            }
            
            # Assess different resource types
            # This would be expanded with actual Azure resource assessments
            # For now, we'll create a placeholder
            
            # Storage accounts assessment
            storage_findings = await self._assess_azure_storage_accounts(context)
            all_findings.extend(storage_findings)
            
            # Network security groups assessment
            nsg_findings = await self._assess_azure_network_security_groups(context)
            all_findings.extend(nsg_findings)
            
            total_resources = len(all_findings)
            
        except Exception as e:
            self.logger.error(f"Error assessing Azure subscription {subscription_id}: {e}")
        
        # Calculate summary metrics
        findings_by_severity = {}
        for severity in Severity:
            findings_by_severity[severity] = len([f for f in all_findings if f.severity == severity])
        
        critical_high_findings = len([f for f in all_findings if f.severity in [Severity.CRITICAL, Severity.HIGH]])
        compliance_score = max(0, (total_resources - critical_high_findings) / total_resources * 100) if total_resources > 0 else 100
        
        end_time = datetime.utcnow()
        execution_time = (end_time - start_time).total_seconds()
        
        result = AssessmentResult(
            assessment_id=f"azure_{subscription_id}_{int(start_time.timestamp())}",
            timestamp=start_time,
            cloud_provider="azure",
            account_id=subscription_id,
            region="global",
            total_resources_assessed=total_resources,
            total_findings=len(all_findings),
            findings_by_severity=findings_by_severity,
            compliance_score=compliance_score,
            findings=all_findings,
            execution_time_seconds=execution_time
        )
        
        self.assessment_results.append(result)
        self.logger.info(f"Azure assessment completed: {len(all_findings)} findings, {compliance_score:.1f}% compliance score")
        
        return result
    
    async def _assess_azure_storage_accounts(self, context: Dict[str, Any]) -> List[SecurityFinding]:
        """Assess Azure Storage Accounts (placeholder implementation)"""
        # This would contain actual Azure storage account assessment logic
        return []
    
    async def _assess_azure_network_security_groups(self, context: Dict[str, Any]) -> List[SecurityFinding]:
        """Assess Azure Network Security Groups (placeholder implementation)"""
        # This would contain actual Azure NSG assessment logic
        return []
    
    async def assess_gcp_project(self, project_id: str) -> AssessmentResult:
        """Assess GCP project security configuration"""
        start_time = datetime.utcnow()
        all_findings = []
        total_resources = 0
        
        self.logger.info(f"Starting GCP assessment for project {project_id}")
        
        try:
            context = {
                'cloud_provider': 'gcp',
                'account_id': project_id,
                'region': 'global'
            }
            
            # Assess different resource types
            # This would be expanded with actual GCP resource assessments
            # For now, we'll create a placeholder
            
            total_resources = len(all_findings)
            
        except Exception as e:
            self.logger.error(f"Error assessing GCP project {project_id}: {e}")
        
        # Calculate summary metrics
        findings_by_severity = {}
        for severity in Severity:
            findings_by_severity[severity] = len([f for f in all_findings if f.severity == severity])
        
        critical_high_findings = len([f for f in all_findings if f.severity in [Severity.CRITICAL, Severity.HIGH]])
        compliance_score = max(0, (total_resources - critical_high_findings) / total_resources * 100) if total_resources > 0 else 100
        
        end_time = datetime.utcnow()
        execution_time = (end_time - start_time).total_seconds()
        
        result = AssessmentResult(
            assessment_id=f"gcp_{project_id}_{int(start_time.timestamp())}",
            timestamp=start_time,
            cloud_provider="gcp",
            account_id=project_id,
            region="global",
            total_resources_assessed=total_resources,
            total_findings=len(all_findings),
            findings_by_severity=findings_by_severity,
            compliance_score=compliance_score,
            findings=all_findings,
            execution_time_seconds=execution_time
        )
        
        self.assessment_results.append(result)
        self.logger.info(f"GCP assessment completed: {len(all_findings)} findings, {compliance_score:.1f}% compliance score")
        
        return result
    
    def get_compliance_report(self, framework: ComplianceFramework) -> Dict[str, Any]:
        """Generate compliance report for specific framework"""
        if not self.assessment_results:
            return {'error': 'No assessment results available'}
        
        # Get latest assessment results
        latest_results = {}
        for result in self.assessment_results:
            key = f"{result.cloud_provider}_{result.account_id}"
            if key not in latest_results or result.timestamp > latest_results[key].timestamp:
                latest_results[key] = result
        
        # Filter findings by framework
        framework_findings = []
        for result in latest_results.values():
            for finding in result.findings:
                if framework in finding.compliance_frameworks:
                    framework_findings.append(finding)
        
        # Calculate compliance metrics
        total_checks = len([rule for rule in self.rules.values() if framework in rule.compliance_frameworks])
        passed_checks = total_checks - len(framework_findings)
        compliance_percentage = (passed_checks / total_checks * 100) if total_checks > 0 else 100
        
        # Group findings by severity
        findings_by_severity = {}
        for severity in Severity:
            findings_by_severity[severity.value] = len([f for f in framework_findings if f.severity == severity])
        
        return {
            'framework': framework.value,
            'assessment_timestamp': datetime.utcnow().isoformat(),
            'total_checks': total_checks,
            'passed_checks': passed_checks,
            'failed_checks': len(framework_findings),
            'compliance_percentage': compliance_percentage,
            'findings_by_severity': findings_by_severity,
            'findings': [
                {
                    'finding_id': f.finding_id,
                    'rule_id': f.rule_id,
                    'resource_id': f.resource_id,
                    'cloud_provider': f.cloud_provider,
                    'severity': f.severity.value,
                    'title': f.title,
                    'description': f.description
                }
                for f in framework_findings
            ]
        }
    
    async def run_scheduled_assessment(self):
        """Run scheduled assessment across all configured cloud providers"""
        self.logger.info("Starting scheduled security configuration assessment")
        
        providers = self.config.get('cloud_providers', ['aws', 'azure', 'gcp'])
        
        for provider in providers:
            try:
                if provider == 'aws':
                    # Get AWS accounts from config
                    aws_accounts = self.config.get('aws_accounts', [])
                    for account_id in aws_accounts:
                        await self.assess_aws_account(account_id)
                
                elif provider == 'azure':
                    # Get Azure subscriptions from config
                    azure_subscriptions = self.config.get('azure_subscriptions', [])
                    for subscription_id in azure_subscriptions:
                        await self.assess_azure_subscription(subscription_id)
                
                elif provider == 'gcp':
                    # Get GCP projects from config
                    gcp_projects = self.config.get('gcp_projects', [])
                    for project_id in gcp_projects:
                        await self.assess_gcp_project(project_id)
                
            except Exception as e:
                self.logger.error(f"Error assessing {provider}: {e}")
        
        self.logger.info("Scheduled security configuration assessment completed")


async def main():
    """Main function for testing the security configuration assessment engine"""
    engine = SecurityConfigurationAssessmentEngine()
    
    # Example: Assess AWS account
    try:
        # This would use actual AWS credentials and account ID
        # result = await engine.assess_aws_account("123456789012", ["us-east-1", "us-west-2"])
        # print(f"Assessment completed: {result.total_findings} findings")
        
        # Generate compliance report
        # report = engine.get_compliance_report(ComplianceFramework.CIS_AWS_FOUNDATIONS)
        # print(json.dumps(report, indent=2))
        
        print("Security Configuration Assessment Engine initialized successfully")
        print(f"Loaded {len(engine.rules)} security rules")
        
    except Exception as e:
        print(f"Error running assessment: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())