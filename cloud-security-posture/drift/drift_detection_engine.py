#!/usr/bin/env python3
"""
iSECTECH Cloud Security Posture Management - Drift Detection and Configuration Management
Continuous monitoring and detection of configuration drift from established baselines
"""

import asyncio
import hashlib
import json
import logging
import yaml
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Any, Set, Union, Tuple

import boto3
from azure.identity import DefaultAzureCredential
from azure.mgmt.resource import ResourceManagementClient
from google.cloud import asset_v1


class DriftSeverity(Enum):
    """Drift detection severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class DriftType(Enum):
    """Types of configuration drift"""
    CONFIGURATION_CHANGE = "configuration_change"
    PERMISSION_CHANGE = "permission_change"
    POLICY_CHANGE = "policy_change"
    RESOURCE_ADDITION = "resource_addition"
    RESOURCE_DELETION = "resource_deletion"
    SECURITY_SETTING_CHANGE = "security_setting_change"
    COMPLIANCE_VIOLATION = "compliance_violation"


class BaselineStatus(Enum):
    """Status of configuration baseline"""
    ACTIVE = "active"
    OUTDATED = "outdated"
    PENDING_APPROVAL = "pending_approval"
    DEPRECATED = "deprecated"


@dataclass
class ConfigurationBaseline:
    """Configuration baseline definition"""
    baseline_id: str
    name: str
    description: str
    cloud_provider: str
    resource_type: str
    account_id: str
    region: str
    baseline_config: Dict[str, Any]
    config_hash: str
    created_timestamp: datetime
    last_updated: datetime
    status: BaselineStatus = BaselineStatus.ACTIVE
    version: int = 1
    approved_by: Optional[str] = None
    tags: Dict[str, str] = field(default_factory=dict)
    compliance_frameworks: List[str] = field(default_factory=list)
    monitoring_enabled: bool = True


@dataclass
class ConfigurationSnapshot:
    """Point-in-time configuration snapshot"""
    snapshot_id: str
    resource_id: str
    resource_type: str
    cloud_provider: str
    account_id: str
    region: str
    configuration: Dict[str, Any]
    config_hash: str
    timestamp: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DriftDetection:
    """Detected configuration drift"""
    drift_id: str
    baseline_id: str
    resource_id: str
    resource_type: str
    cloud_provider: str
    account_id: str
    region: str
    drift_type: DriftType
    severity: DriftSeverity
    title: str
    description: str
    expected_config: Dict[str, Any]
    actual_config: Dict[str, Any]
    config_diff: Dict[str, Any]
    detected_timestamp: datetime
    risk_assessment: str
    remediation_suggestions: List[str]
    compliance_impact: List[str] = field(default_factory=list)
    auto_remediation_available: bool = False
    acknowledged: bool = False
    acknowledged_by: Optional[str] = None
    acknowledged_timestamp: Optional[datetime] = None


@dataclass
class DriftAnalysisResult:
    """Result of drift analysis"""
    analysis_id: str
    timestamp: datetime
    cloud_provider: str
    account_id: str
    total_baselines: int
    total_resources_monitored: int
    detected_drifts: List[DriftDetection]
    drift_summary: Dict[DriftSeverity, int]
    high_priority_drifts: List[str]
    auto_remediation_candidates: List[str]
    compliance_violations: List[str]
    recommendations: List[Dict[str, Any]]
    execution_time_seconds: float


class DriftDetectionEngine:
    """Main drift detection and configuration management engine"""
    
    def __init__(self, config_path: str = "/etc/nsm/drift_detection.yaml"):
        self.config_path = config_path
        self.config = self._load_config()
        self.logger = self._setup_logging()
        
        # Storage for baselines and snapshots
        self.baselines: Dict[str, ConfigurationBaseline] = {}
        self.snapshots: List[ConfigurationSnapshot] = []
        self.detected_drifts: List[DriftDetection] = []
        
        # Configuration monitoring settings
        self.monitored_resource_types = {
            'aws': [
                's3_bucket', 'security_group', 'iam_role', 'iam_policy', 'iam_user',
                'lambda_function', 'rds_instance', 'ec2_instance', 'cloudtrail',
                'config_recorder', 'kms_key'
            ],
            'azure': [
                'storage_account', 'network_security_group', 'virtual_machine',
                'key_vault', 'sql_server', 'app_service'
            ],
            'gcp': [
                'storage_bucket', 'compute_instance', 'cloud_function',
                'sql_instance', 'iam_policy', 'service_account'
            ]
        }
        
        # Drift detection rules
        self.drift_rules = self._load_drift_rules()
        
        # Analysis results storage
        self.analysis_results: List[DriftAnalysisResult] = []
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration"""
        try:
            with open(self.config_path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            print(f"Error loading config: {e}, using defaults")
            return {
                'drift_detection_schedule': '0 */4 * * *',  # Every 4 hours
                'snapshot_retention_days': 30,
                'baseline_auto_update': False,
                'enable_auto_remediation': False,
                'critical_drift_notification': True,
                'compliance_monitoring': True,
                'drift_threshold_percentage': 10.0
            }
    
    def _setup_logging(self) -> logging.Logger:
        """Setup logging"""
        logger = logging.getLogger('DriftDetectionEngine')
        logger.setLevel(logging.INFO)
        
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        
        return logger
    
    def _load_drift_rules(self) -> Dict[str, Any]:
        """Load drift detection rules"""
        return {
            'security_configuration': {
                'description': 'Monitor changes to security-related configurations',
                'severity': DriftSeverity.HIGH,
                'resource_types': ['security_group', 'iam_policy', 'iam_role'],
                'monitored_fields': ['permissions', 'trust_relationships', 'ingress_rules', 'egress_rules']
            },
            'encryption_settings': {
                'description': 'Monitor changes to encryption configurations',
                'severity': DriftSeverity.HIGH,
                'resource_types': ['s3_bucket', 'rds_instance', 'storage_account'],
                'monitored_fields': ['encryption_enabled', 'encryption_key', 'ssl_enforcement']
            },
            'network_configuration': {
                'description': 'Monitor network security configuration changes',
                'severity': DriftSeverity.MEDIUM,
                'resource_types': ['security_group', 'network_security_group', 'firewall_rule'],
                'monitored_fields': ['allowed_ports', 'source_addresses', 'destination_addresses']
            },
            'access_logging': {
                'description': 'Monitor access logging configuration changes',
                'severity': DriftSeverity.MEDIUM,
                'resource_types': ['s3_bucket', 'cloudtrail', 'activity_log'],
                'monitored_fields': ['logging_enabled', 'log_destination', 'retention_period']
            },
            'compliance_settings': {
                'description': 'Monitor compliance-related configuration changes',
                'severity': DriftSeverity.HIGH,
                'resource_types': ['*'],
                'monitored_fields': ['backup_enabled', 'monitoring_enabled', 'tagging']
            }
        }
    
    async def create_baseline(self, resource_id: str, resource_type: str, cloud_provider: str,
                            account_id: str, region: str, config_data: Dict[str, Any],
                            name: str = None, description: str = None) -> ConfigurationBaseline:
        """Create a new configuration baseline"""
        
        # Generate configuration hash
        config_str = json.dumps(config_data, sort_keys=True)
        config_hash = hashlib.sha256(config_str.encode()).hexdigest()
        
        baseline = ConfigurationBaseline(
            baseline_id=f"baseline_{cloud_provider}_{resource_type}_{resource_id}_{int(datetime.utcnow().timestamp())}",
            name=name or f"{resource_type} Baseline for {resource_id}",
            description=description or f"Configuration baseline for {resource_type} {resource_id}",
            cloud_provider=cloud_provider,
            resource_type=resource_type,
            account_id=account_id,
            region=region,
            baseline_config=config_data,
            config_hash=config_hash,
            created_timestamp=datetime.utcnow(),
            last_updated=datetime.utcnow()
        )
        
        self.baselines[baseline.baseline_id] = baseline
        self.logger.info(f"Created baseline {baseline.baseline_id} for resource {resource_id}")
        
        return baseline
    
    async def capture_configuration_snapshot(self, resource_id: str, resource_type: str,
                                           cloud_provider: str, account_id: str, region: str) -> Optional[ConfigurationSnapshot]:
        """Capture current configuration snapshot of a resource"""
        
        try:
            # Get current configuration based on cloud provider
            if cloud_provider == 'aws':
                config_data = await self._get_aws_resource_config(resource_id, resource_type, region)
            elif cloud_provider == 'azure':
                config_data = await self._get_azure_resource_config(resource_id, resource_type, account_id)
            elif cloud_provider == 'gcp':
                config_data = await self._get_gcp_resource_config(resource_id, resource_type, account_id)
            else:
                raise ValueError(f"Unsupported cloud provider: {cloud_provider}")
            
            if not config_data:
                self.logger.warning(f"Could not retrieve configuration for resource {resource_id}")
                return None
            
            # Generate configuration hash
            config_str = json.dumps(config_data, sort_keys=True)
            config_hash = hashlib.sha256(config_str.encode()).hexdigest()
            
            snapshot = ConfigurationSnapshot(
                snapshot_id=f"snapshot_{cloud_provider}_{resource_id}_{int(datetime.utcnow().timestamp())}",
                resource_id=resource_id,
                resource_type=resource_type,
                cloud_provider=cloud_provider,
                account_id=account_id,
                region=region,
                configuration=config_data,
                config_hash=config_hash,
                timestamp=datetime.utcnow()
            )
            
            self.snapshots.append(snapshot)
            self.logger.debug(f"Captured configuration snapshot for resource {resource_id}")
            
            return snapshot
            
        except Exception as e:
            self.logger.error(f"Error capturing snapshot for resource {resource_id}: {e}")
            return None
    
    async def _get_aws_resource_config(self, resource_id: str, resource_type: str, region: str) -> Dict[str, Any]:
        """Get AWS resource configuration"""
        session = boto3.Session(region_name=region)
        
        try:
            if resource_type == 's3_bucket':
                return await self._get_aws_s3_config(resource_id, session)
            elif resource_type == 'security_group':
                return await self._get_aws_sg_config(resource_id, session)
            elif resource_type == 'iam_role':
                return await self._get_aws_iam_role_config(resource_id, session)
            elif resource_type == 'iam_policy':
                return await self._get_aws_iam_policy_config(resource_id, session)
            elif resource_type == 'lambda_function':
                return await self._get_aws_lambda_config(resource_id, session)
            else:
                self.logger.warning(f"AWS resource type {resource_type} not implemented")
                return {}
        except Exception as e:
            self.logger.error(f"Error getting AWS {resource_type} config: {e}")
            return {}
    
    async def _get_aws_s3_config(self, bucket_name: str, session: boto3.Session) -> Dict[str, Any]:
        """Get S3 bucket configuration"""
        s3_client = session.client('s3')
        config = {'bucket_name': bucket_name}
        
        try:
            # Bucket versioning
            versioning = s3_client.get_bucket_versioning(Bucket=bucket_name)
            config['versioning_status'] = versioning.get('Status', 'Disabled')
            
            # Bucket encryption
            try:
                encryption = s3_client.get_bucket_encryption(Bucket=bucket_name)
                config['encryption_enabled'] = True
                config['encryption_config'] = encryption['ServerSideEncryptionConfiguration']
            except s3_client.exceptions.ClientError:
                config['encryption_enabled'] = False
            
            # Public access block
            try:
                public_access = s3_client.get_public_access_block(Bucket=bucket_name)
                config['public_access_block'] = public_access['PublicAccessBlockConfiguration']
            except s3_client.exceptions.ClientError:
                config['public_access_block'] = None
            
            # Bucket logging
            try:
                logging_config = s3_client.get_bucket_logging(Bucket=bucket_name)
                config['logging_enabled'] = 'LoggingEnabled' in logging_config
                if config['logging_enabled']:
                    config['logging_config'] = logging_config['LoggingEnabled']
            except s3_client.exceptions.ClientError:
                config['logging_enabled'] = False
            
            # Bucket policy
            try:
                policy = s3_client.get_bucket_policy(Bucket=bucket_name)
                config['policy'] = json.loads(policy['Policy'])
            except s3_client.exceptions.ClientError:
                config['policy'] = None
            
        except Exception as e:
            self.logger.error(f"Error getting S3 bucket {bucket_name} config: {e}")
        
        return config
    
    async def _get_aws_sg_config(self, sg_id: str, session: boto3.Session) -> Dict[str, Any]:
        """Get Security Group configuration"""
        ec2_client = session.client('ec2')
        
        try:
            response = ec2_client.describe_security_groups(GroupIds=[sg_id])
            sg = response['SecurityGroups'][0]
            
            return {
                'group_id': sg['GroupId'],
                'group_name': sg['GroupName'],
                'description': sg['Description'],
                'vpc_id': sg.get('VpcId'),
                'ingress_rules': sg.get('IpPermissions', []),
                'egress_rules': sg.get('IpPermissionsEgress', []),
                'tags': {tag['Key']: tag['Value'] for tag in sg.get('Tags', [])}
            }
        except Exception as e:
            self.logger.error(f"Error getting security group {sg_id} config: {e}")
            return {}
    
    async def _get_aws_iam_role_config(self, role_name: str, session: boto3.Session) -> Dict[str, Any]:
        """Get IAM Role configuration"""
        iam_client = session.client('iam')
        
        try:
            # Get role details
            role_response = iam_client.get_role(RoleName=role_name)
            role = role_response['Role']
            
            # Get attached policies
            attached_policies = iam_client.list_attached_role_policies(RoleName=role_name)
            
            # Get inline policies
            inline_policies = iam_client.list_role_policies(RoleName=role_name)
            
            return {
                'role_name': role['RoleName'],
                'role_id': role['RoleId'],
                'arn': role['Arn'],
                'assume_role_policy_document': role['AssumeRolePolicyDocument'],
                'description': role.get('Description', ''),
                'max_session_duration': role.get('MaxSessionDuration'),
                'attached_policies': [p['PolicyArn'] for p in attached_policies['AttachedPolicies']],
                'inline_policies': inline_policies['PolicyNames'],
                'tags': {tag['Key']: tag['Value'] for tag in role.get('Tags', [])}
            }
        except Exception as e:
            self.logger.error(f"Error getting IAM role {role_name} config: {e}")
            return {}
    
    async def _get_azure_resource_config(self, resource_id: str, resource_type: str, subscription_id: str) -> Dict[str, Any]:
        """Get Azure resource configuration (placeholder)"""
        # This would contain actual Azure resource configuration retrieval
        return {}
    
    async def _get_gcp_resource_config(self, resource_id: str, resource_type: str, project_id: str) -> Dict[str, Any]:
        """Get GCP resource configuration (placeholder)"""
        # This would contain actual GCP resource configuration retrieval
        return {}
    
    async def detect_drift(self, baseline_id: str, current_snapshot: ConfigurationSnapshot) -> List[DriftDetection]:
        """Detect configuration drift against baseline"""
        
        if baseline_id not in self.baselines:
            raise ValueError(f"Baseline {baseline_id} not found")
        
        baseline = self.baselines[baseline_id]
        detected_drifts = []
        
        # Compare configuration hashes first
        if baseline.config_hash == current_snapshot.config_hash:
            self.logger.debug(f"No drift detected for resource {current_snapshot.resource_id}")
            return detected_drifts
        
        # Detailed drift analysis
        config_diff = self._calculate_config_diff(baseline.baseline_config, current_snapshot.configuration)
        
        if not config_diff:
            return detected_drifts
        
        # Analyze each difference
        for field_path, changes in config_diff.items():
            drift_type, severity = self._classify_drift(field_path, changes, baseline.resource_type)
            
            drift = DriftDetection(
                drift_id=f"drift_{baseline_id}_{field_path}_{int(datetime.utcnow().timestamp())}",
                baseline_id=baseline_id,
                resource_id=current_snapshot.resource_id,
                resource_type=current_snapshot.resource_type,
                cloud_provider=current_snapshot.cloud_provider,
                account_id=current_snapshot.account_id,
                region=current_snapshot.region,
                drift_type=drift_type,
                severity=severity,
                title=f"Configuration drift detected in {field_path}",
                description=f"Configuration field {field_path} has changed from baseline",
                expected_config={field_path: changes.get('expected')},
                actual_config={field_path: changes.get('actual')},
                config_diff=config_diff,
                detected_timestamp=datetime.utcnow(),
                risk_assessment=self._assess_drift_risk(field_path, changes, baseline.resource_type),
                remediation_suggestions=self._generate_remediation_suggestions(field_path, changes, baseline.resource_type),
                compliance_impact=self._assess_compliance_impact(field_path, changes, baseline.compliance_frameworks)
            )
            
            detected_drifts.append(drift)
        
        # Store detected drifts
        self.detected_drifts.extend(detected_drifts)
        
        self.logger.info(f"Detected {len(detected_drifts)} configuration drifts for resource {current_snapshot.resource_id}")
        
        return detected_drifts
    
    def _calculate_config_diff(self, baseline_config: Dict[str, Any], current_config: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate configuration differences"""
        differences = {}
        
        # Check all keys in baseline
        for key, baseline_value in baseline_config.items():
            current_value = current_config.get(key)
            
            if isinstance(baseline_value, dict) and isinstance(current_value, dict):
                nested_diff = self._calculate_config_diff(baseline_value, current_value)
                if nested_diff:
                    differences[key] = nested_diff
            elif baseline_value != current_value:
                differences[key] = {
                    'expected': baseline_value,
                    'actual': current_value,
                    'change_type': 'modified' if current_value is not None else 'removed'
                }
        
        # Check for new keys in current config
        for key, current_value in current_config.items():
            if key not in baseline_config:
                differences[key] = {
                    'expected': None,
                    'actual': current_value,
                    'change_type': 'added'
                }
        
        return differences
    
    def _classify_drift(self, field_path: str, changes: Dict[str, Any], resource_type: str) -> Tuple[DriftType, DriftSeverity]:
        """Classify the type and severity of drift"""
        
        change_type = changes.get('change_type', 'modified')
        
        # Determine drift type
        if 'policy' in field_path.lower() or 'permission' in field_path.lower():
            drift_type = DriftType.POLICY_CHANGE
        elif 'security' in field_path.lower() or 'encryption' in field_path.lower():
            drift_type = DriftType.SECURITY_SETTING_CHANGE
        elif change_type == 'added':
            drift_type = DriftType.RESOURCE_ADDITION
        elif change_type == 'removed':
            drift_type = DriftType.RESOURCE_DELETION
        else:
            drift_type = DriftType.CONFIGURATION_CHANGE
        
        # Determine severity based on field and resource type
        severity = DriftSeverity.MEDIUM  # Default
        
        # High severity fields
        high_severity_fields = [
            'encryption', 'security', 'policy', 'permission', 'access',
            'public', 'trust_relationship', 'assume_role'
        ]
        
        if any(field in field_path.lower() for field in high_severity_fields):
            severity = DriftSeverity.HIGH
        
        # Critical severity for security-related changes
        critical_fields = ['public_access_block', 'assume_role_policy_document', 'ingress_rules']
        if any(field in field_path.lower() for field in critical_fields):
            severity = DriftSeverity.CRITICAL
        
        # Low severity for cosmetic changes
        low_severity_fields = ['description', 'tags', 'name']
        if any(field in field_path.lower() for field in low_severity_fields):
            severity = DriftSeverity.LOW
        
        return drift_type, severity
    
    def _assess_drift_risk(self, field_path: str, changes: Dict[str, Any], resource_type: str) -> str:
        """Assess the risk impact of detected drift"""
        
        expected = changes.get('expected')
        actual = changes.get('actual')
        change_type = changes.get('change_type')
        
        # Security-related risks
        if 'encryption' in field_path.lower():
            if actual is False or actual is None:
                return "HIGH RISK: Encryption has been disabled, potentially exposing sensitive data"
            else:
                return "MEDIUM RISK: Encryption configuration has changed"
        
        if 'public_access' in field_path.lower():
            if actual is True or 'public' in str(actual).lower():
                return "CRITICAL RISK: Resource may be exposed to public access"
            else:
                return "LOW RISK: Public access restrictions have been modified"
        
        if 'policy' in field_path.lower() or 'permission' in field_path.lower():
            if change_type == 'added':
                return "MEDIUM RISK: New permissions have been granted"
            elif change_type == 'removed':
                return "MEDIUM RISK: Permissions have been removed, may affect functionality"
            else:
                return "MEDIUM RISK: Permission policies have been modified"
        
        # Network security risks
        if 'ingress_rules' in field_path.lower() or 'egress_rules' in field_path.lower():
            return "HIGH RISK: Network access rules have been modified"
        
        # Default risk assessment
        if change_type == 'removed':
            return "MEDIUM RISK: Configuration has been removed"
        elif change_type == 'added':
            return "LOW RISK: New configuration has been added"
        else:
            return "LOW RISK: Configuration has been modified"
    
    def _generate_remediation_suggestions(self, field_path: str, changes: Dict[str, Any], resource_type: str) -> List[str]:
        """Generate remediation suggestions for detected drift"""
        
        suggestions = []
        expected = changes.get('expected')
        change_type = changes.get('change_type')
        
        if change_type == 'modified':
            suggestions.append(f"Restore {field_path} to expected value: {expected}")
            suggestions.append("Review change management process to prevent unauthorized modifications")
            suggestions.append("Implement additional access controls if needed")
        
        elif change_type == 'removed':
            suggestions.append(f"Restore missing configuration: {field_path}")
            suggestions.append("Investigate why the configuration was removed")
            suggestions.append("Implement monitoring to detect future removals")
        
        elif change_type == 'added':
            suggestions.append(f"Review new configuration: {field_path}")
            suggestions.append("Verify the new configuration is authorized and necessary")
            suggestions.append("Update baseline if the change is approved")
        
        # Specific suggestions based on field type
        if 'encryption' in field_path.lower():
            suggestions.append("Ensure encryption is enabled with appropriate key management")
            suggestions.append("Review compliance requirements for encryption")
        
        if 'public_access' in field_path.lower():
            suggestions.append("Review public access requirements")
            suggestions.append("Implement least privilege access principles")
            suggestions.append("Consider using VPC endpoints or private access methods")
        
        if 'policy' in field_path.lower():
            suggestions.append("Review policy changes with security team")
            suggestions.append("Ensure policy follows principle of least privilege")
            suggestions.append("Update documentation to reflect approved changes")
        
        return suggestions
    
    def _assess_compliance_impact(self, field_path: str, changes: Dict[str, Any], frameworks: List[str]) -> List[str]:
        """Assess compliance framework impact"""
        
        impact = []
        
        for framework in frameworks:
            if framework.upper() == 'CIS':
                if 'encryption' in field_path.lower():
                    impact.append("CIS: May violate encryption requirements")
                if 'public_access' in field_path.lower():
                    impact.append("CIS: May violate public access restrictions")
                if 'logging' in field_path.lower():
                    impact.append("CIS: May violate logging requirements")
            
            elif framework.upper() == 'SOC2':
                if 'security' in field_path.lower() or 'access' in field_path.lower():
                    impact.append("SOC2: May impact access control requirements")
                if 'encryption' in field_path.lower():
                    impact.append("SOC2: May violate data protection requirements")
            
            elif framework.upper() == 'PCI-DSS':
                if 'encryption' in field_path.lower():
                    impact.append("PCI-DSS: May violate data encryption requirements")
                if 'network' in field_path.lower() or 'firewall' in field_path.lower():
                    impact.append("PCI-DSS: May impact network security requirements")
        
        return impact
    
    async def run_drift_analysis(self, cloud_provider: str, account_id: str, regions: List[str] = None) -> DriftAnalysisResult:
        """Run comprehensive drift analysis"""
        
        start_time = datetime.utcnow()
        self.logger.info(f"Starting drift analysis for {cloud_provider} account {account_id}")
        
        if regions is None:
            regions = ['us-east-1'] if cloud_provider == 'aws' else ['global']
        
        all_detected_drifts = []
        resources_monitored = 0
        
        # Get relevant baselines
        relevant_baselines = [
            baseline for baseline in self.baselines.values()
            if (baseline.cloud_provider == cloud_provider and 
                baseline.account_id == account_id and
                baseline.status == BaselineStatus.ACTIVE)
        ]
        
        for baseline in relevant_baselines:
            try:
                # Capture current snapshot
                current_snapshot = await self.capture_configuration_snapshot(
                    baseline.baseline_config.get('resource_id', baseline.baseline_id.split('_')[-2]),
                    baseline.resource_type,
                    baseline.cloud_provider,
                    baseline.account_id,
                    baseline.region
                )
                
                if current_snapshot:
                    resources_monitored += 1
                    
                    # Detect drift
                    drifts = await self.detect_drift(baseline.baseline_id, current_snapshot)
                    all_detected_drifts.extend(drifts)
            
            except Exception as e:
                self.logger.error(f"Error analyzing baseline {baseline.baseline_id}: {e}")
        
        # Calculate summary metrics
        drift_summary = {}
        for severity in DriftSeverity:
            drift_summary[severity] = len([d for d in all_detected_drifts if d.severity == severity])
        
        high_priority_drifts = [
            d.drift_id for d in all_detected_drifts 
            if d.severity in [DriftSeverity.CRITICAL, DriftSeverity.HIGH]
        ]
        
        auto_remediation_candidates = [
            d.drift_id for d in all_detected_drifts 
            if d.auto_remediation_available
        ]
        
        compliance_violations = [
            d.drift_id for d in all_detected_drifts 
            if d.compliance_impact
        ]
        
        # Generate recommendations
        recommendations = self._generate_drift_recommendations(all_detected_drifts)
        
        end_time = datetime.utcnow()
        execution_time = (end_time - start_time).total_seconds()
        
        result = DriftAnalysisResult(
            analysis_id=f"drift_analysis_{cloud_provider}_{account_id}_{int(start_time.timestamp())}",
            timestamp=start_time,
            cloud_provider=cloud_provider,
            account_id=account_id,
            total_baselines=len(relevant_baselines),
            total_resources_monitored=resources_monitored,
            detected_drifts=all_detected_drifts,
            drift_summary=drift_summary,
            high_priority_drifts=high_priority_drifts,
            auto_remediation_candidates=auto_remediation_candidates,
            compliance_violations=compliance_violations,
            recommendations=recommendations,
            execution_time_seconds=execution_time
        )
        
        self.analysis_results.append(result)
        self.logger.info(f"Drift analysis completed: {len(all_detected_drifts)} drifts detected")
        
        return result
    
    def _generate_drift_recommendations(self, detected_drifts: List[DriftDetection]) -> List[Dict[str, Any]]:
        """Generate recommendations based on detected drifts"""
        
        recommendations = []
        
        if not detected_drifts:
            recommendations.append({
                'priority': 'info',
                'category': 'status',
                'title': 'No configuration drift detected',
                'description': 'All monitored resources are aligned with their baselines',
                'impact': 'Maintain current monitoring and baseline management practices'
            })
            return recommendations
        
        # Critical drifts
        critical_drifts = [d for d in detected_drifts if d.severity == DriftSeverity.CRITICAL]
        if critical_drifts:
            recommendations.append({
                'priority': 'critical',
                'category': 'immediate_action',
                'title': f'Address {len(critical_drifts)} critical configuration drifts',
                'description': 'Critical security configuration changes detected that require immediate attention',
                'impact': 'High risk of security breach or compliance violation',
                'affected_resources': [d.resource_id for d in critical_drifts[:5]]
            })
        
        # High priority drifts
        high_drifts = [d for d in detected_drifts if d.severity == DriftSeverity.HIGH]
        if high_drifts:
            recommendations.append({
                'priority': 'high',
                'category': 'security_review',
                'title': f'Review {len(high_drifts)} high-severity configuration changes',
                'description': 'Security-related configuration changes that may impact system security',
                'impact': 'Potential security vulnerabilities or compliance issues',
                'affected_resources': [d.resource_id for d in high_drifts[:5]]
            })
        
        # Compliance violations
        compliance_drifts = [d for d in detected_drifts if d.compliance_impact]
        if compliance_drifts:
            recommendations.append({
                'priority': 'high',
                'category': 'compliance',
                'title': f'Address {len(compliance_drifts)} compliance-related drifts',
                'description': 'Configuration changes that may impact compliance with regulatory frameworks',
                'impact': 'Potential compliance violations and audit findings',
                'frameworks': list(set(framework for d in compliance_drifts for framework in d.compliance_impact))
            })
        
        # Auto-remediation opportunities
        auto_drifts = [d for d in detected_drifts if d.auto_remediation_available]
        if auto_drifts:
            recommendations.append({
                'priority': 'medium',
                'category': 'automation',
                'title': f'Enable auto-remediation for {len(auto_drifts)} drifts',
                'description': 'Configuration drifts that can be automatically remediated',
                'impact': 'Reduce manual effort and improve response time',
                'affected_resources': [d.resource_id for d in auto_drifts[:5]]
            })
        
        # General recommendations
        recommendations.append({
            'priority': 'medium',
            'category': 'process_improvement',
            'title': 'Strengthen configuration management processes',
            'description': 'Implement additional controls to prevent unauthorized configuration changes',
            'impact': 'Reduce future configuration drift incidents',
            'actions': [
                'Review and update change management procedures',
                'Implement additional access controls',
                'Increase monitoring frequency for critical resources',
                'Provide training on configuration management best practices'
            ]
        })
        
        return recommendations
    
    def generate_drift_report(self, output_format: str = 'json') -> str:
        """Generate drift detection report"""
        
        if not self.analysis_results:
            return "No drift analysis results available"
        
        latest_result = max(self.analysis_results, key=lambda x: x.timestamp)
        
        if output_format.lower() == 'json':
            return json.dumps(asdict(latest_result), indent=2, default=str)
        
        else:  # text format
            report = []
            report.append("CONFIGURATION DRIFT DETECTION REPORT")
            report.append("=" * 60)
            report.append(f"Analysis ID: {latest_result.analysis_id}")
            report.append(f"Timestamp: {latest_result.timestamp}")
            report.append(f"Cloud Provider: {latest_result.cloud_provider}")
            report.append(f"Account ID: {latest_result.account_id}")
            report.append(f"Baselines Monitored: {latest_result.total_baselines}")
            report.append(f"Resources Monitored: {latest_result.total_resources_monitored}")
            report.append(f"Total Drifts Detected: {len(latest_result.detected_drifts)}")
            report.append(f"Execution Time: {latest_result.execution_time_seconds:.1f} seconds")
            report.append("")
            
            # Drift summary
            if latest_result.drift_summary:
                report.append("DRIFT SUMMARY BY SEVERITY:")
                report.append("-" * 40)
                for severity, count in latest_result.drift_summary.items():
                    if count > 0:
                        report.append(f"  {severity.value.title()}: {count}")
                report.append("")
            
            # High priority drifts
            if latest_result.high_priority_drifts:
                report.append("HIGH PRIORITY DRIFTS:")
                report.append("-" * 30)
                high_priority_details = [
                    d for d in latest_result.detected_drifts 
                    if d.drift_id in latest_result.high_priority_drifts
                ]
                for drift in high_priority_details[:10]:  # Show top 10
                    report.append(f"• {drift.title} ({drift.severity.value})")
                    report.append(f"  Resource: {drift.resource_id}")
                    report.append(f"  Risk: {drift.risk_assessment}")
                    report.append("")
            
            # Compliance violations
            if latest_result.compliance_violations:
                report.append("COMPLIANCE VIOLATIONS:")
                report.append("-" * 30)
                compliance_details = [
                    d for d in latest_result.detected_drifts 
                    if d.drift_id in latest_result.compliance_violations
                ]
                for drift in compliance_details[:5]:  # Show top 5
                    report.append(f"• {drift.title}")
                    report.append(f"  Impact: {', '.join(drift.compliance_impact)}")
                    report.append("")
            
            # Recommendations
            if latest_result.recommendations:
                report.append("RECOMMENDATIONS:")
                report.append("-" * 30)
                for rec in latest_result.recommendations:
                    report.append(f"• {rec['title']} (Priority: {rec['priority']})")
                    report.append(f"  {rec['description']}")
                    report.append("")
            
            return "\n".join(report)
    
    def cleanup_old_snapshots(self):
        """Clean up old configuration snapshots"""
        retention_days = self.config.get('snapshot_retention_days', 30)
        cutoff_date = datetime.utcnow() - timedelta(days=retention_days)
        
        initial_count = len(self.snapshots)
        self.snapshots = [s for s in self.snapshots if s.timestamp > cutoff_date]
        
        cleaned_count = initial_count - len(self.snapshots)
        if cleaned_count > 0:
            self.logger.info(f"Cleaned up {cleaned_count} old configuration snapshots")


async def main():
    """Main function for testing drift detection engine"""
    engine = DriftDetectionEngine()
    
    try:
        print("Drift Detection and Configuration Management Engine initialized successfully")
        print(f"Monitoring {sum(len(types) for types in engine.monitored_resource_types.values())} resource types")
        print(f"Loaded {len(engine.drift_rules)} drift detection rules")
        
        # Example: Create a baseline and detect drift (would need actual resources)
        # baseline = await engine.create_baseline(
        #     "my-bucket", "s3_bucket", "aws", "123456789012", "us-east-1",
        #     {"encryption_enabled": True, "public_access_blocked": True}
        # )
        # print(f"Created baseline: {baseline.baseline_id}")
        
        # Example: Run drift analysis
        # result = await engine.run_drift_analysis("aws", "123456789012", ["us-east-1"])
        # print(f"Drift analysis completed: {len(result.detected_drifts)} drifts detected")
        
        # Generate report
        # report = engine.generate_drift_report('text')
        # print(report)
        
    except Exception as e:
        print(f"Error running drift detection engine: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())