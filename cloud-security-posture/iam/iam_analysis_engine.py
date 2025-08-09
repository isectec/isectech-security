#!/usr/bin/env python3
"""
iSECTECH Cloud Security Posture Management - IAM Analysis and Least Privilege Enforcement
Advanced IAM analysis for identifying excessive permissions and enforcing least privilege access
"""

import asyncio
import json
import logging
import re
from collections import defaultdict, Counter
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Any, Set, Tuple, Union

import boto3
import yaml
from azure.identity import DefaultAzureCredential
from azure.mgmt.authorization import AuthorizationManagementClient
from azure.mgmt.resource import ResourceManagementClient
from google.cloud import asset_v1, iam_v1
from google.oauth2 import service_account


class RiskLevel(Enum):
    """IAM risk levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AccessType(Enum):
    """Types of access permissions"""
    READ = "read"
    WRITE = "write"
    ADMIN = "admin"
    FULL_ACCESS = "full_access"
    SERVICE = "service"
    CROSS_ACCOUNT = "cross_account"


@dataclass
class IAMPermission:
    """Individual IAM permission"""
    service: str
    action: str
    resource: str
    effect: str  # Allow/Deny
    condition: Optional[Dict[str, Any]] = None
    access_type: AccessType = AccessType.READ
    risk_score: float = 0.0


@dataclass
class IAMRole:
    """IAM role or user definition"""
    id: str
    name: str
    type: str  # user, role, group, service_account
    cloud_provider: str
    account_id: str
    created_date: datetime
    last_used: Optional[datetime] = None
    permissions: List[IAMPermission] = field(default_factory=list)
    attached_policies: List[str] = field(default_factory=list)
    inline_policies: List[str] = field(default_factory=list)
    trust_relationships: List[Dict[str, Any]] = field(default_factory=list)
    tags: Dict[str, str] = field(default_factory=dict)
    is_service_account: bool = False
    is_cross_account: bool = False
    risk_score: float = 0.0


@dataclass
class IAMPolicy:
    """IAM policy definition"""
    id: str
    name: str
    type: str  # managed, inline, custom
    cloud_provider: str
    account_id: str
    document: Dict[str, Any]
    attached_to: List[str] = field(default_factory=list)
    permissions: List[IAMPermission] = field(default_factory=list)
    risk_score: float = 0.0
    is_aws_managed: bool = False
    version: str = "1"


@dataclass
class IAMViolation:
    """IAM security violation"""
    violation_id: str
    rule_id: str
    entity_id: str
    entity_type: str  # user, role, policy
    entity_name: str
    cloud_provider: str
    account_id: str
    risk_level: RiskLevel
    title: str
    description: str
    current_permissions: List[str]
    recommended_permissions: List[str]
    impact: str
    remediation_steps: List[str]
    timestamp: datetime
    last_used_data: Optional[Dict[str, Any]] = None
    compliance_frameworks: List[str] = field(default_factory=list)


@dataclass
class PrivilegeAnalysisResult:
    """Result of privilege analysis"""
    analysis_id: str
    timestamp: datetime
    cloud_provider: str
    account_id: str
    total_entities: int
    high_risk_entities: int
    violations: List[IAMViolation]
    unused_permissions: Dict[str, List[str]]
    over_privileged_entities: List[str]
    dormant_entities: List[str]
    cross_account_access: List[str]
    privilege_escalation_paths: List[Dict[str, Any]]
    recommendations: List[Dict[str, Any]]
    risk_score: float
    execution_time_seconds: float


class IAMAnalysisEngine:
    """Main IAM analysis and least privilege enforcement engine"""
    
    def __init__(self, config_path: str = "/etc/nsm/iam_analysis.yaml"):
        self.config_path = config_path
        self.config = self._load_config()
        self.logger = self._setup_logging()
        
        # Risk scoring weights
        self.risk_weights = {
            'admin_permissions': 10.0,
            'cross_account_access': 8.0,
            'unused_permissions': 6.0,
            'overly_broad_permissions': 7.0,
            'no_mfa': 5.0,
            'dormant_account': 4.0,
            'privilege_escalation': 9.0,
            'service_account_misuse': 6.0
        }
        
        # High-risk AWS actions
        self.high_risk_aws_actions = {
            'iam:*', 'sts:AssumeRole', '*:*', 'iam:CreateRole', 'iam:AttachRolePolicy',
            'iam:PutRolePolicy', 'iam:CreateUser', 'iam:AttachUserPolicy', 'iam:PutUserPolicy',
            'ec2:*', 's3:*', 'lambda:*', 'iam:PassRole', 'sts:AssumeRoleWithWebIdentity'
        }
        
        # Analysis results storage
        self.analysis_results: List[PrivilegeAnalysisResult] = []
        
        # Load privilege analysis rules
        self.analysis_rules = self._load_analysis_rules()
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration"""
        try:
            with open(self.config_path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            print(f"Error loading config: {e}, using defaults")
            return {
                'analysis_schedule': '0 3 * * *',  # Daily at 3 AM
                'dormant_threshold_days': 90,
                'unused_permission_threshold_days': 30,
                'max_privilege_score': 100.0,
                'enable_automated_remediation': False,
                'remediation_dry_run': True
            }
    
    def _setup_logging(self) -> logging.Logger:
        """Setup logging"""
        logger = logging.getLogger('IAMAnalysisEngine')
        logger.setLevel(logging.INFO)
        
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        
        return logger
    
    def _load_analysis_rules(self) -> Dict[str, Any]:
        """Load IAM analysis rules"""
        return {
            'excessive_permissions': {
                'description': 'Identify entities with more permissions than needed',
                'risk_level': RiskLevel.HIGH,
                'check_function': 'check_excessive_permissions'
            },
            'dormant_entities': {
                'description': 'Identify entities that have not been used recently',
                'risk_level': RiskLevel.MEDIUM,
                'check_function': 'check_dormant_entities'
            },
            'admin_access': {
                'description': 'Identify entities with administrative access',
                'risk_level': RiskLevel.CRITICAL,
                'check_function': 'check_admin_access'
            },
            'cross_account_access': {
                'description': 'Identify cross-account access configurations',
                'risk_level': RiskLevel.HIGH,
                'check_function': 'check_cross_account_access'
            },
            'privilege_escalation': {
                'description': 'Identify potential privilege escalation paths',
                'risk_level': RiskLevel.CRITICAL,
                'check_function': 'check_privilege_escalation'
            },
            'no_mfa_admin': {
                'description': 'Identify admin entities without MFA',
                'risk_level': RiskLevel.HIGH,
                'check_function': 'check_mfa_requirement'
            }
        }
    
    async def analyze_aws_iam(self, account_id: str, regions: List[str] = None) -> PrivilegeAnalysisResult:
        """Analyze AWS IAM configuration"""
        if regions is None:
            regions = ['us-east-1']  # IAM is global, but we need one region for API calls
        
        start_time = datetime.utcnow()
        self.logger.info(f"Starting AWS IAM analysis for account {account_id}")
        
        try:
            # Initialize AWS session
            session = boto3.Session(region_name=regions[0])
            iam_client = session.client('iam')
            
            # Collect IAM entities
            users = await self._collect_aws_users(iam_client, account_id)
            roles = await self._collect_aws_roles(iam_client, account_id)
            policies = await self._collect_aws_policies(iam_client, account_id)
            
            all_entities = users + roles
            
            # Analyze each entity
            violations = []
            unused_permissions = defaultdict(list)
            over_privileged_entities = []
            dormant_entities = []
            cross_account_access = []
            privilege_escalation_paths = []
            
            for entity in all_entities:
                # Calculate risk score
                entity.risk_score = self._calculate_entity_risk_score(entity)
                
                # Run violation checks
                entity_violations = await self._run_violation_checks(entity, policies)
                violations.extend(entity_violations)
                
                # Check for specific conditions
                if entity.risk_score > 70:
                    over_privileged_entities.append(entity.name)
                
                if self._is_dormant_entity(entity):
                    dormant_entities.append(entity.name)
                
                if entity.is_cross_account:
                    cross_account_access.append(entity.name)
                
                # Check for privilege escalation paths
                escalation_paths = self._find_privilege_escalation_paths(entity)
                privilege_escalation_paths.extend(escalation_paths)
                
                # Identify unused permissions
                unused_perms = self._identify_unused_permissions(entity)
                if unused_perms:
                    unused_permissions[entity.name] = unused_perms
            
            # Generate recommendations
            recommendations = self._generate_remediation_recommendations(
                violations, over_privileged_entities, dormant_entities
            )
            
            # Calculate overall risk score
            high_risk_entities = len([e for e in all_entities if e.risk_score > 70])
            overall_risk = min(100.0, (high_risk_entities / len(all_entities)) * 100) if all_entities else 0
            
            end_time = datetime.utcnow()
            execution_time = (end_time - start_time).total_seconds()
            
            result = PrivilegeAnalysisResult(
                analysis_id=f"aws_iam_{account_id}_{int(start_time.timestamp())}",
                timestamp=start_time,
                cloud_provider="aws",
                account_id=account_id,
                total_entities=len(all_entities),
                high_risk_entities=high_risk_entities,
                violations=violations,
                unused_permissions=dict(unused_permissions),
                over_privileged_entities=over_privileged_entities,
                dormant_entities=dormant_entities,
                cross_account_access=cross_account_access,
                privilege_escalation_paths=privilege_escalation_paths,
                recommendations=recommendations,
                risk_score=overall_risk,
                execution_time_seconds=execution_time
            )
            
            self.analysis_results.append(result)
            self.logger.info(f"AWS IAM analysis completed: {len(violations)} violations, {overall_risk:.1f}% risk score")
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error analyzing AWS IAM: {e}")
            raise
    
    async def _collect_aws_users(self, iam_client, account_id: str) -> List[IAMRole]:
        """Collect AWS IAM users"""
        users = []
        
        try:
            paginator = iam_client.get_paginator('list_users')
            for page in paginator.paginate():
                for user_data in page['Users']:
                    user = IAMRole(
                        id=user_data['UserId'],
                        name=user_data['UserName'],
                        type='user',
                        cloud_provider='aws',
                        account_id=account_id,
                        created_date=user_data['CreateDate'],
                        last_used=user_data.get('PasswordLastUsed'),
                        tags=self._extract_aws_tags(user_data.get('Tags', []))
                    )
                    
                    # Get user policies
                    user.attached_policies = await self._get_aws_user_policies(iam_client, user.name)
                    user.inline_policies = await self._get_aws_user_inline_policies(iam_client, user.name)
                    
                    # Get user permissions
                    user.permissions = await self._get_aws_user_permissions(iam_client, user.name)
                    
                    # Check for cross-account access
                    user.is_cross_account = self._check_aws_cross_account_access(user.permissions)
                    
                    users.append(user)
        
        except Exception as e:
            self.logger.error(f"Error collecting AWS users: {e}")
        
        return users
    
    async def _collect_aws_roles(self, iam_client, account_id: str) -> List[IAMRole]:
        """Collect AWS IAM roles"""
        roles = []
        
        try:
            paginator = iam_client.get_paginator('list_roles')
            for page in paginator.paginate():
                for role_data in page['Roles']:
                    role = IAMRole(
                        id=role_data['RoleId'],
                        name=role_data['RoleName'],
                        type='role',
                        cloud_provider='aws',
                        account_id=account_id,
                        created_date=role_data['CreateDate'],
                        tags=self._extract_aws_tags(role_data.get('Tags', [])),
                        is_service_account=self._is_aws_service_role(role_data)
                    )
                    
                    # Get trust relationships
                    trust_policy = role_data.get('AssumeRolePolicyDocument')
                    if trust_policy:
                        role.trust_relationships = [trust_policy]
                    
                    # Get role policies
                    role.attached_policies = await self._get_aws_role_policies(iam_client, role.name)
                    role.inline_policies = await self._get_aws_role_inline_policies(iam_client, role.name)
                    
                    # Get role permissions
                    role.permissions = await self._get_aws_role_permissions(iam_client, role.name)
                    
                    # Check for cross-account access
                    role.is_cross_account = self._check_aws_cross_account_access(role.permissions, trust_policy)
                    
                    # Get last used information
                    try:
                        role_usage = iam_client.get_role(RoleName=role.name)
                        role.last_used = role_usage.get('Role', {}).get('RoleLastUsed', {}).get('LastUsedDate')
                    except Exception:
                        pass
                    
                    roles.append(role)
        
        except Exception as e:
            self.logger.error(f"Error collecting AWS roles: {e}")
        
        return roles
    
    async def _collect_aws_policies(self, iam_client, account_id: str) -> List[IAMPolicy]:
        """Collect AWS IAM policies"""
        policies = []
        
        try:
            # Get customer managed policies
            paginator = iam_client.get_paginator('list_policies')
            for page in paginator.paginate(Scope='Local'):
                for policy_data in page['Policies']:
                    policy = IAMPolicy(
                        id=policy_data['PolicyId'],
                        name=policy_data['PolicyName'],
                        type='managed',
                        cloud_provider='aws',
                        account_id=account_id,
                        document={},
                        version=policy_data.get('DefaultVersionId', 'v1')
                    )
                    
                    # Get policy document
                    try:
                        policy_version = iam_client.get_policy_version(
                            PolicyArn=policy_data['Arn'],
                            VersionId=policy.version
                        )
                        policy.document = policy_version['PolicyVersion']['Document']
                        policy.permissions = self._parse_aws_policy_permissions(policy.document)
                        policy.risk_score = self._calculate_policy_risk_score(policy)
                    except Exception as e:
                        self.logger.warning(f"Could not get policy document for {policy.name}: {e}")
                    
                    policies.append(policy)
        
        except Exception as e:
            self.logger.error(f"Error collecting AWS policies: {e}")
        
        return policies
    
    def _extract_aws_tags(self, tags_list: List[Dict[str, str]]) -> Dict[str, str]:
        """Extract tags from AWS tags list format"""
        return {tag['Key']: tag['Value'] for tag in tags_list}
    
    def _is_aws_service_role(self, role_data: Dict[str, Any]) -> bool:
        """Check if AWS role is a service role"""
        assume_policy = role_data.get('AssumeRolePolicyDocument', {})
        if not assume_policy:
            return False
        
        statements = assume_policy.get('Statement', [])
        for statement in statements:
            principals = statement.get('Principal', {})
            if isinstance(principals, dict):
                services = principals.get('Service', [])
                if isinstance(services, str):
                    services = [services]
                if any('.amazonaws.com' in service for service in services):
                    return True
        
        return False
    
    async def _get_aws_user_policies(self, iam_client, username: str) -> List[str]:
        """Get attached policies for AWS user"""
        try:
            response = iam_client.list_attached_user_policies(UserName=username)
            return [policy['PolicyArn'] for policy in response['AttachedPolicies']]
        except Exception:
            return []
    
    async def _get_aws_user_inline_policies(self, iam_client, username: str) -> List[str]:
        """Get inline policies for AWS user"""
        try:
            response = iam_client.list_user_policies(UserName=username)
            return response['PolicyNames']
        except Exception:
            return []
    
    async def _get_aws_role_policies(self, iam_client, rolename: str) -> List[str]:
        """Get attached policies for AWS role"""
        try:
            response = iam_client.list_attached_role_policies(RoleName=rolename)
            return [policy['PolicyArn'] for policy in response['AttachedPolicies']]
        except Exception:
            return []
    
    async def _get_aws_role_inline_policies(self, iam_client, rolename: str) -> List[str]:
        """Get inline policies for AWS role"""
        try:
            response = iam_client.list_role_policies(RoleName=rolename)
            return response['PolicyNames']
        except Exception:
            return []
    
    async def _get_aws_user_permissions(self, iam_client, username: str) -> List[IAMPermission]:
        """Get effective permissions for AWS user"""
        permissions = []
        
        try:
            # Get attached managed policies
            attached_policies = iam_client.list_attached_user_policies(UserName=username)
            for policy in attached_policies['AttachedPolicies']:
                policy_perms = await self._get_aws_policy_permissions(iam_client, policy['PolicyArn'])
                permissions.extend(policy_perms)
            
            # Get inline policies
            inline_policies = iam_client.list_user_policies(UserName=username)
            for policy_name in inline_policies['PolicyNames']:
                policy_doc = iam_client.get_user_policy(UserName=username, PolicyName=policy_name)
                policy_perms = self._parse_aws_policy_permissions(policy_doc['PolicyDocument'])
                permissions.extend(policy_perms)
            
            # Get group policies
            user_groups = iam_client.get_groups_for_user(UserName=username)
            for group in user_groups['Groups']:
                group_perms = await self._get_aws_group_permissions(iam_client, group['GroupName'])
                permissions.extend(group_perms)
        
        except Exception as e:
            self.logger.warning(f"Error getting permissions for user {username}: {e}")
        
        return permissions
    
    async def _get_aws_role_permissions(self, iam_client, rolename: str) -> List[IAMPermission]:
        """Get effective permissions for AWS role"""
        permissions = []
        
        try:
            # Get attached managed policies
            attached_policies = iam_client.list_attached_role_policies(RoleName=rolename)
            for policy in attached_policies['AttachedPolicies']:
                policy_perms = await self._get_aws_policy_permissions(iam_client, policy['PolicyArn'])
                permissions.extend(policy_perms)
            
            # Get inline policies
            inline_policies = iam_client.list_role_policies(RoleName=rolename)
            for policy_name in inline_policies['PolicyNames']:
                policy_doc = iam_client.get_role_policy(RoleName=rolename, PolicyName=policy_name)
                policy_perms = self._parse_aws_policy_permissions(policy_doc['PolicyDocument'])
                permissions.extend(policy_perms)
        
        except Exception as e:
            self.logger.warning(f"Error getting permissions for role {rolename}: {e}")
        
        return permissions
    
    async def _get_aws_group_permissions(self, iam_client, groupname: str) -> List[IAMPermission]:
        """Get effective permissions for AWS group"""
        permissions = []
        
        try:
            # Get attached managed policies
            attached_policies = iam_client.list_attached_group_policies(GroupName=groupname)
            for policy in attached_policies['AttachedPolicies']:
                policy_perms = await self._get_aws_policy_permissions(iam_client, policy['PolicyArn'])
                permissions.extend(policy_perms)
            
            # Get inline policies
            inline_policies = iam_client.list_group_policies(GroupName=groupname)
            for policy_name in inline_policies['PolicyNames']:
                policy_doc = iam_client.get_group_policy(GroupName=groupname, PolicyName=policy_name)
                policy_perms = self._parse_aws_policy_permissions(policy_doc['PolicyDocument'])
                permissions.extend(policy_perms)
        
        except Exception as e:
            self.logger.warning(f"Error getting permissions for group {groupname}: {e}")
        
        return permissions
    
    async def _get_aws_policy_permissions(self, iam_client, policy_arn: str) -> List[IAMPermission]:
        """Get permissions from AWS policy"""
        try:
            policy = iam_client.get_policy(PolicyArn=policy_arn)
            policy_version = iam_client.get_policy_version(
                PolicyArn=policy_arn,
                VersionId=policy['Policy']['DefaultVersionId']
            )
            return self._parse_aws_policy_permissions(policy_version['PolicyVersion']['Document'])
        except Exception:
            return []
    
    def _parse_aws_policy_permissions(self, policy_document: Dict[str, Any]) -> List[IAMPermission]:
        """Parse AWS policy document to extract permissions"""
        permissions = []
        
        statements = policy_document.get('Statement', [])
        if isinstance(statements, dict):
            statements = [statements]
        
        for statement in statements:
            effect = statement.get('Effect', 'Allow')
            actions = statement.get('Action', [])
            resources = statement.get('Resource', ['*'])
            condition = statement.get('Condition')
            
            if isinstance(actions, str):
                actions = [actions]
            if isinstance(resources, str):
                resources = [resources]
            
            for action in actions:
                for resource in resources:
                    # Parse service and action
                    if ':' in action:
                        service, action_name = action.split(':', 1)
                    else:
                        service, action_name = action, '*'
                    
                    # Determine access type
                    access_type = self._classify_aws_access_type(action, resource)
                    
                    # Calculate risk score
                    risk_score = self._calculate_permission_risk_score(action, resource, effect)
                    
                    permission = IAMPermission(
                        service=service,
                        action=action_name,
                        resource=resource,
                        effect=effect,
                        condition=condition,
                        access_type=access_type,
                        risk_score=risk_score
                    )
                    permissions.append(permission)
        
        return permissions
    
    def _classify_aws_access_type(self, action: str, resource: str) -> AccessType:
        """Classify AWS action access type"""
        action_lower = action.lower()
        
        if action == '*:*' or (action.endswith(':*') and resource == '*'):
            return AccessType.FULL_ACCESS
        
        if any(admin_action in action_lower for admin_action in ['admin', 'manage', 'full', '*']):
            return AccessType.ADMIN
        
        if any(write_action in action_lower for write_action in ['create', 'delete', 'update', 'put', 'post', 'write']):
            return AccessType.WRITE
        
        if 'assumerole' in action_lower or 'cross' in resource.lower():
            return AccessType.CROSS_ACCOUNT
        
        if '.amazonaws.com' in resource or action.startswith('sts:'):
            return AccessType.SERVICE
        
        return AccessType.READ
    
    def _calculate_permission_risk_score(self, action: str, resource: str, effect: str) -> float:
        """Calculate risk score for individual permission"""
        if effect == 'Deny':
            return 0.0
        
        risk_score = 1.0
        
        # High-risk actions
        if action in self.high_risk_aws_actions or action == '*:*':
            risk_score *= 10.0
        elif action.endswith(':*'):
            risk_score *= 5.0
        elif any(high_risk in action.lower() for high_risk in ['admin', 'full', 'manage']):
            risk_score *= 3.0
        
        # Resource scope
        if resource == '*':
            risk_score *= 3.0
        elif '*' in resource:
            risk_score *= 2.0
        
        return min(10.0, risk_score)
    
    def _calculate_entity_risk_score(self, entity: IAMRole) -> float:
        """Calculate overall risk score for IAM entity"""
        risk_score = 0.0
        
        # Base score from permissions
        if entity.permissions:
            avg_permission_risk = sum(p.risk_score for p in entity.permissions) / len(entity.permissions)
            risk_score += avg_permission_risk * 5.0
        
        # Administrative permissions
        admin_permissions = [p for p in entity.permissions if p.access_type == AccessType.ADMIN]
        if admin_permissions:
            risk_score += self.risk_weights['admin_permissions']
        
        # Cross-account access
        if entity.is_cross_account:
            risk_score += self.risk_weights['cross_account_access']
        
        # Dormant entity
        if self._is_dormant_entity(entity):
            risk_score += self.risk_weights['dormant_account']
        
        # Service account with user-like permissions
        if entity.is_service_account and len(entity.permissions) > 10:
            risk_score += self.risk_weights['service_account_misuse']
        
        return min(100.0, risk_score)
    
    def _calculate_policy_risk_score(self, policy: IAMPolicy) -> float:
        """Calculate risk score for IAM policy"""
        if not policy.permissions:
            return 0.0
        
        # Average permission risk
        avg_risk = sum(p.risk_score for p in policy.permissions) / len(policy.permissions)
        
        # Additional factors
        if any(p.action == '*:*' for p in policy.permissions):
            avg_risk *= 2.0
        
        if policy.is_aws_managed:
            avg_risk *= 0.5  # AWS managed policies are generally safer
        
        return min(100.0, avg_risk * 10.0)
    
    def _check_aws_cross_account_access(self, permissions: List[IAMPermission], 
                                      trust_policy: Dict[str, Any] = None) -> bool:
        """Check if entity has cross-account access"""
        # Check permissions for cross-account actions
        for permission in permissions:
            if permission.access_type == AccessType.CROSS_ACCOUNT:
                return True
            if 'sts:assumerole' in permission.action.lower():
                return True
        
        # Check trust policy for cross-account principals
        if trust_policy:
            statements = trust_policy.get('Statement', [])
            if isinstance(statements, dict):
                statements = [statements]
            
            for statement in statements:
                principals = statement.get('Principal', {})
                if isinstance(principals, dict):
                    aws_principals = principals.get('AWS', [])
                    if isinstance(aws_principals, str):
                        aws_principals = [aws_principals]
                    
                    for principal in aws_principals:
                        if isinstance(principal, str) and ':' in principal:
                            account_id = principal.split(':')[4]
                            # This would need actual account context to determine if it's cross-account
                            # For now, we'll check if it's a different format
                            if account_id != '*' and len(account_id) == 12:
                                return True
        
        return False
    
    def _is_dormant_entity(self, entity: IAMRole) -> bool:
        """Check if entity is dormant (not used recently)"""
        if not entity.last_used:
            return True
        
        threshold_date = datetime.utcnow() - timedelta(days=self.config.get('dormant_threshold_days', 90))
        return entity.last_used < threshold_date
    
    def _find_privilege_escalation_paths(self, entity: IAMRole) -> List[Dict[str, Any]]:
        """Find potential privilege escalation paths"""
        escalation_paths = []
        
        # Check for IAM permissions that could lead to privilege escalation
        dangerous_permissions = [
            'iam:CreateRole', 'iam:AttachRolePolicy', 'iam:PutRolePolicy',
            'iam:CreateUser', 'iam:AttachUserPolicy', 'iam:PutUserPolicy',
            'iam:PassRole', 'sts:AssumeRole'
        ]
        
        for permission in entity.permissions:
            full_action = f"{permission.service}:{permission.action}"
            if full_action in dangerous_permissions or permission.action == '*':
                escalation_paths.append({
                    'entity_id': entity.id,
                    'entity_name': entity.name,
                    'permission': full_action,
                    'resource': permission.resource,
                    'risk_level': 'high',
                    'description': f"Can potentially escalate privileges via {full_action}"
                })
        
        return escalation_paths
    
    def _identify_unused_permissions(self, entity: IAMRole) -> List[str]:
        """Identify permissions that appear to be unused"""
        # This is a simplified implementation
        # In practice, you'd analyze CloudTrail logs or access advisor data
        unused_permissions = []
        
        # For demonstration, we'll flag overly broad permissions as potentially unused
        for permission in entity.permissions:
            if permission.resource == '*' and permission.action.endswith('*'):
                if permission.access_type == AccessType.ADMIN:
                    unused_permissions.append(f"{permission.service}:{permission.action}")
        
        return unused_permissions
    
    async def _run_violation_checks(self, entity: IAMRole, policies: List[IAMPolicy]) -> List[IAMViolation]:
        """Run violation checks against IAM entity"""
        violations = []
        
        # Check for excessive permissions
        if entity.risk_score > 80:
            violations.append(IAMViolation(
                violation_id=f"excessive_perms_{entity.id}_{int(datetime.utcnow().timestamp())}",
                rule_id="excessive_permissions",
                entity_id=entity.id,
                entity_type=entity.type,
                entity_name=entity.name,
                cloud_provider=entity.cloud_provider,
                account_id=entity.account_id,
                risk_level=RiskLevel.HIGH,
                title="Excessive Permissions Detected",
                description=f"Entity {entity.name} has a high risk score of {entity.risk_score:.1f}",
                current_permissions=[f"{p.service}:{p.action}" for p in entity.permissions[:10]],
                recommended_permissions=["Review and remove unnecessary permissions"],
                impact="High risk of privilege abuse or lateral movement",
                remediation_steps=[
                    "Review entity's actual usage patterns",
                    "Remove unused permissions",
                    "Apply principle of least privilege",
                    "Monitor entity activity"
                ],
                timestamp=datetime.utcnow(),
                compliance_frameworks=["CIS", "NIST"]
            ))
        
        # Check for dormant entities
        if self._is_dormant_entity(entity):
            violations.append(IAMViolation(
                violation_id=f"dormant_{entity.id}_{int(datetime.utcnow().timestamp())}",
                rule_id="dormant_entities",
                entity_id=entity.id,
                entity_type=entity.type,
                entity_name=entity.name,
                cloud_provider=entity.cloud_provider,
                account_id=entity.account_id,
                risk_level=RiskLevel.MEDIUM,
                title="Dormant Entity Detected",
                description=f"Entity {entity.name} has not been used recently",
                current_permissions=[f"{p.service}:{p.action}" for p in entity.permissions[:5]],
                recommended_permissions=["Consider disabling or removing"],
                impact="Increased attack surface from unused accounts",
                remediation_steps=[
                    "Verify if entity is still needed",
                    "Disable or remove if unused",
                    "Document business justification if kept"
                ],
                timestamp=datetime.utcnow(),
                last_used_data={'last_used': entity.last_used.isoformat() if entity.last_used else None}
            ))
        
        # Check for admin access
        admin_permissions = [p for p in entity.permissions if p.access_type == AccessType.ADMIN]
        if admin_permissions:
            violations.append(IAMViolation(
                violation_id=f"admin_access_{entity.id}_{int(datetime.utcnow().timestamp())}",
                rule_id="admin_access",
                entity_id=entity.id,
                entity_type=entity.type,
                entity_name=entity.name,
                cloud_provider=entity.cloud_provider,
                account_id=entity.account_id,
                risk_level=RiskLevel.CRITICAL,
                title="Administrative Access Detected",
                description=f"Entity {entity.name} has administrative permissions",
                current_permissions=[f"{p.service}:{p.action}" for p in admin_permissions],
                recommended_permissions=["Review necessity of admin access"],
                impact="High risk of system compromise",
                remediation_steps=[
                    "Verify business justification for admin access",
                    "Implement break-glass procedures",
                    "Enable MFA for admin access",
                    "Monitor admin activities closely"
                ],
                timestamp=datetime.utcnow(),
                compliance_frameworks=["CIS", "SOC2", "PCI-DSS"]
            ))
        
        return violations
    
    def _generate_remediation_recommendations(self, violations: List[IAMViolation],
                                            over_privileged: List[str],
                                            dormant: List[str]) -> List[Dict[str, Any]]:
        """Generate remediation recommendations"""
        recommendations = []
        
        if violations:
            recommendations.append({
                'priority': 'high',
                'category': 'violations',
                'title': f'Address {len(violations)} IAM violations',
                'description': 'Review and remediate identified IAM security violations',
                'impact': 'Reduce security risk and improve compliance posture'
            })
        
        if over_privileged:
            recommendations.append({
                'priority': 'high',
                'category': 'least_privilege',
                'title': f'Apply least privilege to {len(over_privileged)} entities',
                'description': 'Remove excessive permissions from over-privileged entities',
                'entities': over_privileged[:10],  # Limit for readability
                'impact': 'Reduce blast radius of potential security incidents'
            })
        
        if dormant:
            recommendations.append({
                'priority': 'medium',
                'category': 'cleanup',
                'title': f'Review {len(dormant)} dormant entities',
                'description': 'Disable or remove entities that have not been used recently',
                'entities': dormant[:10],
                'impact': 'Reduce attack surface and improve security hygiene'
            })
        
        # General recommendations
        recommendations.append({
            'priority': 'medium',
            'category': 'monitoring',
            'title': 'Implement continuous IAM monitoring',
            'description': 'Set up automated monitoring for IAM changes and usage patterns',
            'impact': 'Early detection of privilege abuse and policy drift'
        })
        
        return recommendations
    
    async def generate_least_privilege_policies(self, entity: IAMRole, 
                                              usage_data: Dict[str, Any] = None) -> Dict[str, Any]:
        """Generate least privilege policies based on usage data"""
        if not usage_data:
            # In practice, this would analyze CloudTrail logs or access advisor data
            usage_data = {'actions_used': [], 'resources_accessed': []}
        
        used_actions = set(usage_data.get('actions_used', []))
        used_resources = set(usage_data.get('resources_accessed', []))
        
        # Generate minimal policy
        minimal_policy = {
            'Version': '2012-10-17',
            'Statement': []
        }
        
        # Group actions by service
        actions_by_service = defaultdict(list)
        for action in used_actions:
            if ':' in action:
                service, action_name = action.split(':', 1)
                actions_by_service[service].append(action_name)
        
        # Create statements for each service
        for service, actions in actions_by_service.items():
            statement = {
                'Effect': 'Allow',
                'Action': [f"{service}:{action}" for action in actions]
            }
            
            # Add resource restrictions if available
            service_resources = [r for r in used_resources if service in r.lower()]
            if service_resources:
                statement['Resource'] = service_resources
            else:
                statement['Resource'] = '*'  # Default to all resources if no specific data
            
            minimal_policy['Statement'].append(statement)
        
        return {
            'entity_id': entity.id,
            'entity_name': entity.name,
            'current_policy_count': len(entity.attached_policies) + len(entity.inline_policies),
            'recommended_policy': minimal_policy,
            'removed_permissions': len(entity.permissions) - len(used_actions),
            'risk_reduction': max(0, entity.risk_score - 30.0),  # Estimated risk reduction
            'recommendations': [
                'Review the generated minimal policy carefully',
                'Test in a non-production environment first',
                'Monitor for access denied errors after implementation',
                'Gradually tighten permissions over time'
            ]
        }
    
    def export_analysis_results(self, output_format: str = 'json') -> str:
        """Export analysis results in specified format"""
        if not self.analysis_results:
            return "No analysis results available"
        
        latest_result = max(self.analysis_results, key=lambda x: x.timestamp)
        
        if output_format.lower() == 'json':
            return json.dumps(asdict(latest_result), indent=2, default=str)
        
        elif output_format.lower() == 'csv':
            import csv
            import io
            
            output = io.StringIO()
            writer = csv.writer(output)
            
            # Write violations
            writer.writerow(['Entity Name', 'Risk Level', 'Title', 'Description', 'Remediation'])
            for violation in latest_result.violations:
                writer.writerow([
                    violation.entity_name,
                    violation.risk_level.value,
                    violation.title,
                    violation.description,
                    '; '.join(violation.remediation_steps)
                ])
            
            return output.getvalue()
        
        else:
            # Text format
            report = []
            report.append("IAM ANALYSIS REPORT")
            report.append("=" * 50)
            report.append(f"Analysis ID: {latest_result.analysis_id}")
            report.append(f"Timestamp: {latest_result.timestamp}")
            report.append(f"Cloud Provider: {latest_result.cloud_provider}")
            report.append(f"Account ID: {latest_result.account_id}")
            report.append(f"Total Entities: {latest_result.total_entities}")
            report.append(f"High Risk Entities: {latest_result.high_risk_entities}")
            report.append(f"Total Violations: {len(latest_result.violations)}")
            report.append(f"Risk Score: {latest_result.risk_score:.1f}%")
            report.append("")
            
            if latest_result.violations:
                report.append("VIOLATIONS:")
                report.append("-" * 30)
                for violation in latest_result.violations[:10]:  # Show top 10
                    report.append(f"• {violation.title} ({violation.risk_level.value})")
                    report.append(f"  Entity: {violation.entity_name}")
                    report.append(f"  Impact: {violation.impact}")
                    report.append("")
            
            if latest_result.recommendations:
                report.append("RECOMMENDATIONS:")
                report.append("-" * 30)
                for rec in latest_result.recommendations:
                    report.append(f"• {rec['title']} (Priority: {rec['priority']})")
                    report.append(f"  {rec['description']}")
                    report.append("")
            
            return "\n".join(report)


async def main():
    """Main function for testing IAM analysis engine"""
    engine = IAMAnalysisEngine()
    
    try:
        print("IAM Analysis and Least Privilege Enforcement Engine initialized successfully")
        print(f"Loaded {len(engine.analysis_rules)} analysis rules")
        
        # Example: Analyze AWS account (would need actual credentials)
        # result = await engine.analyze_aws_iam("123456789012")
        # print(f"Analysis completed: {len(result.violations)} violations found")
        
        # Export results
        # report = engine.export_analysis_results('text')
        # print(report)
        
    except Exception as e:
        print(f"Error running IAM analysis: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())