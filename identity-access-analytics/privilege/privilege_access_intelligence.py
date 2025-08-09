"""
Privilege Analysis and Access Intelligence System
Production-grade privilege analysis, role mining, and access intelligence for ISECTECH platform
Author: ISECTECH Security Team
Version: 1.0.0
"""

import asyncio
import logging
import time
import json
import uuid
import hashlib
from typing import Dict, List, Optional, Any, Union, Tuple, Callable, Set
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from collections import defaultdict, Counter
import sqlite3
import aiosqlite
import redis.asyncio as redis
import numpy as np
import pandas as pd
from concurrent.futures import ThreadPoolExecutor
import threading
import math
import networkx as nx
from sklearn.cluster import DBSCAN, KMeans, AgglomerativeClustering
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import silhouette_score
from sklearn.decomposition import PCA
from scipy.spatial.distance import cosine, jaccard
from scipy.stats import chi2_contingency
import itertools
import statistics


class PrivilegeType(Enum):
    """Types of privileges in the system"""
    READ = "read"
    WRITE = "write"
    EXECUTE = "execute"
    DELETE = "delete"
    ADMIN = "admin"
    CREATE = "create"
    MODIFY = "modify"
    APPROVE = "approve"
    AUDIT = "audit"
    BACKUP = "backup"
    RESTORE = "restore"
    CONFIG = "config"
    SECURITY = "security"
    FINANCE = "finance"
    HR = "hr"
    CUSTOM = "custom"


class RiskLevel(Enum):
    """Risk levels for privileges and roles"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    MINIMAL = "minimal"


class AccessPattern(Enum):
    """Access pattern classifications"""
    REGULAR = "regular"
    INFREQUENT = "infrequent"
    NEVER_USED = "never_used"
    RECENTLY_GRANTED = "recently_granted"
    EXCESSIVE = "excessive"
    SUSPICIOUS = "suspicious"


class SoDViolationType(Enum):
    """Segregation of Duties violation types"""
    FINANCIAL_CONTROL = "financial_control"
    SECURITY_ADMIN = "security_admin"
    HR_PAYROLL = "hr_payroll"
    AUDIT_COMPLIANCE = "audit_compliance"
    IT_OPERATIONS = "it_operations"
    DATA_PRIVACY = "data_privacy"
    PROCUREMENT = "procurement"
    CUSTOM = "custom"


@dataclass
class Permission:
    """Individual permission definition"""
    permission_id: str
    name: str
    description: str
    privilege_type: PrivilegeType
    resource_type: str
    resource_identifier: Optional[str] = None
    risk_level: RiskLevel = RiskLevel.MEDIUM
    business_justification: Optional[str] = None
    regulatory_requirement: Optional[str] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_modified: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    active: bool = True


@dataclass
class Role:
    """Role definition with permissions"""
    role_id: str
    name: str
    description: str
    permissions: List[str] = field(default_factory=list)  # Permission IDs
    parent_roles: List[str] = field(default_factory=list)  # Inherited roles
    child_roles: List[str] = field(default_factory=list)  # Sub-roles
    risk_level: RiskLevel = RiskLevel.MEDIUM
    business_owner: Optional[str] = None
    technical_owner: Optional[str] = None
    certification_required: bool = False
    certification_frequency_days: int = 90
    last_certified: Optional[datetime] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_modified: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    active: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class UserAccess:
    """User access assignment"""
    user_id: str
    username: str
    email: Optional[str] = None
    department: Optional[str] = None
    job_title: Optional[str] = None
    manager: Optional[str] = None
    roles: List[str] = field(default_factory=list)  # Role IDs
    direct_permissions: List[str] = field(default_factory=list)  # Direct permission IDs
    effective_permissions: List[str] = field(default_factory=list)  # All permissions
    last_access: Optional[datetime] = None
    access_frequency: Dict[str, int] = field(default_factory=dict)  # Permission ID -> count
    risk_score: float = 0.0
    compliance_status: str = "compliant"
    certification_status: str = "pending"
    last_certification: Optional[datetime] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    active: bool = True


@dataclass
class PrivilegeViolation:
    """Privilege or access violation"""
    violation_id: str
    violation_type: str
    severity: RiskLevel
    user_id: str
    description: str
    details: Dict[str, Any]
    detected_at: datetime
    resolved: bool = False
    resolved_at: Optional[datetime] = None
    false_positive: bool = False
    remediation_actions: List[str] = field(default_factory=list)
    business_impact: Optional[str] = None
    compliance_impact: Optional[str] = None


@dataclass
class SoDRule:
    """Segregation of Duties rule definition"""
    rule_id: str
    name: str
    description: str
    violation_type: SoDViolationType
    conflicting_permissions: List[List[str]]  # Groups of conflicting permission IDs
    conflicting_roles: List[List[str]]  # Groups of conflicting role IDs
    severity: RiskLevel = RiskLevel.HIGH
    regulatory_basis: Optional[str] = None
    business_justification: str = ""
    exceptions: List[str] = field(default_factory=list)  # Approved exception user IDs
    active: bool = True
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class AccessCertificationCampaign:
    """Access certification campaign"""
    campaign_id: str
    name: str
    description: str
    scope: Dict[str, Any]  # What to certify (roles, users, departments)
    start_date: datetime
    end_date: datetime
    certifiers: List[str]  # User IDs of people who can certify
    status: str = "active"  # active, completed, cancelled
    completion_rate: float = 0.0
    violations_found: int = 0
    auto_approve_threshold: float = 0.1  # Risk score below which to auto-approve
    escalation_threshold_days: int = 7
    created_by: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class PrivilegeAnalyzer:
    """Core privilege analysis engine"""
    
    def __init__(self, redis_client: Optional[redis.Redis] = None):
        self.redis_client = redis_client
        self.privilege_weights = {
            PrivilegeType.READ: 1.0,
            PrivilegeType.WRITE: 2.0,
            PrivilegeType.EXECUTE: 2.5,
            PrivilegeType.DELETE: 3.0,
            PrivilegeType.ADMIN: 5.0,
            PrivilegeType.SECURITY: 4.0,
            PrivilegeType.FINANCE: 3.5,
            PrivilegeType.HR: 3.0,
            PrivilegeType.CONFIG: 3.5,
            PrivilegeType.AUDIT: 2.0
        }
    
    async def analyze_excessive_privileges(self, users: List[UserAccess], 
                                         permissions: Dict[str, Permission],
                                         roles: Dict[str, Role],
                                         access_history: Dict[str, List[Dict[str, Any]]]) -> List[PrivilegeViolation]:
        """Analyze users for excessive privileges"""
        violations = []
        
        for user in users:
            # Calculate user's privilege risk score
            risk_score = await self._calculate_user_privilege_risk(user, permissions, roles)
            
            # Get peer group for comparison
            peer_group = await self._find_peer_group(user, users)
            
            # Analyze against peer group
            peer_violations = await self._detect_peer_group_anomalies(user, peer_group, permissions, roles)
            violations.extend(peer_violations)
            
            # Analyze unused permissions
            unused_violations = await self._detect_unused_permissions(user, access_history.get(user.user_id, []), permissions)
            violations.extend(unused_violations)
            
            # Analyze privilege creep
            creep_violations = await self._detect_privilege_creep(user, access_history.get(user.user_id, []), permissions, roles)
            violations.extend(creep_violations)
            
            # Check for high-risk combinations
            combination_violations = await self._detect_risky_privilege_combinations(user, permissions, roles)
            violations.extend(combination_violations)
        
        return violations
    
    async def _calculate_user_privilege_risk(self, user: UserAccess, 
                                           permissions: Dict[str, Permission],
                                           roles: Dict[str, Role]) -> float:
        """Calculate risk score for user's privileges"""
        total_risk = 0.0
        
        # Calculate risk from effective permissions
        for perm_id in user.effective_permissions:
            permission = permissions.get(perm_id)
            if permission:
                # Base risk from privilege type
                base_risk = self.privilege_weights.get(permission.privilege_type, 1.0)
                
                # Risk multiplier based on risk level
                risk_multipliers = {
                    RiskLevel.CRITICAL: 5.0,
                    RiskLevel.HIGH: 3.0,
                    RiskLevel.MEDIUM: 1.5,
                    RiskLevel.LOW: 1.0,
                    RiskLevel.MINIMAL: 0.5
                }
                
                risk_multiplier = risk_multipliers.get(permission.risk_level, 1.0)
                total_risk += base_risk * risk_multiplier
        
        # Normalize risk score (0-100 scale)
        normalized_risk = min(100.0, total_risk / max(len(user.effective_permissions), 1) * 10)
        
        return normalized_risk
    
    async def _find_peer_group(self, user: UserAccess, all_users: List[UserAccess]) -> List[UserAccess]:
        """Find peer group for user based on department, job title, etc."""
        peers = []
        
        for other_user in all_users:
            if other_user.user_id == user.user_id:
                continue
            
            similarity_score = 0.0
            
            # Department similarity
            if user.department and other_user.department:
                if user.department == other_user.department:
                    similarity_score += 0.4
            
            # Job title similarity
            if user.job_title and other_user.job_title:
                if user.job_title == other_user.job_title:
                    similarity_score += 0.3
                elif self._job_title_similarity(user.job_title, other_user.job_title) > 0.5:
                    similarity_score += 0.2
            
            # Manager similarity
            if user.manager and other_user.manager:
                if user.manager == other_user.manager:
                    similarity_score += 0.2
            
            # Role overlap
            common_roles = set(user.roles) & set(other_user.roles)
            if common_roles:
                similarity_score += 0.1 * len(common_roles) / max(len(user.roles), len(other_user.roles))
            
            if similarity_score >= 0.5:  # Threshold for being considered a peer
                peers.append(other_user)
        
        return peers
    
    def _job_title_similarity(self, title1: str, title2: str) -> float:
        """Calculate similarity between job titles"""
        # Simple word-based similarity
        words1 = set(title1.lower().split())
        words2 = set(title2.lower().split())
        
        if not words1 or not words2:
            return 0.0
        
        intersection = words1 & words2
        union = words1 | words2
        
        return len(intersection) / len(union)
    
    async def _detect_peer_group_anomalies(self, user: UserAccess, peers: List[UserAccess],
                                         permissions: Dict[str, Permission],
                                         roles: Dict[str, Role]) -> List[PrivilegeViolation]:
        """Detect privilege anomalies compared to peer group"""
        violations = []
        
        if not peers:
            return violations
        
        # Calculate peer group statistics
        peer_permissions = []
        for peer in peers:
            peer_permissions.extend(peer.effective_permissions)
        
        peer_permission_counts = Counter(peer_permissions)
        total_peers = len(peers)
        
        # Find permissions that are rare in peer group
        user_permissions = set(user.effective_permissions)
        
        for perm_id in user_permissions:
            peer_usage_rate = peer_permission_counts.get(perm_id, 0) / total_peers
            
            # If less than 20% of peers have this permission, it's potentially excessive
            if peer_usage_rate < 0.2:
                permission = permissions.get(perm_id)
                if permission and permission.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
                    violation = PrivilegeViolation(
                        violation_id=str(uuid.uuid4()),
                        violation_type="excessive_privilege_peer_comparison",
                        severity=permission.risk_level,
                        user_id=user.user_id,
                        description=f"User has high-risk permission '{permission.name}' that only {peer_usage_rate*100:.1f}% of peers have",
                        details={
                            'permission_id': perm_id,
                            'permission_name': permission.name,
                            'peer_usage_rate': peer_usage_rate,
                            'peer_count': total_peers,
                            'risk_level': permission.risk_level.value
                        },
                        detected_at=datetime.now(timezone.utc),
                        remediation_actions=[
                            "Review business justification for this permission",
                            "Consider removing if not actively used",
                            "Verify approval was obtained for high-risk permission"
                        ]
                    )
                    violations.append(violation)
        
        return violations
    
    async def _detect_unused_permissions(self, user: UserAccess, 
                                       access_history: List[Dict[str, Any]],
                                       permissions: Dict[str, Permission]) -> List[PrivilegeViolation]:
        """Detect permissions that are never or rarely used"""
        violations = []
        
        # Analyze usage patterns from access history
        usage_counts = defaultdict(int)
        
        for access_event in access_history:
            permission_used = access_event.get('permission_id') or access_event.get('resource')
            if permission_used:
                usage_counts[permission_used] += 1
        
        # Look for unused or rarely used permissions
        for perm_id in user.effective_permissions:
            usage_count = usage_counts.get(perm_id, 0)
            
            # Consider permission unused if not used in the last 90 days
            # and it's been assigned for more than 30 days
            if usage_count == 0:
                permission = permissions.get(perm_id)
                if permission:
                    violation = PrivilegeViolation(
                        violation_id=str(uuid.uuid4()),
                        violation_type="unused_permission",
                        severity=RiskLevel.MEDIUM,
                        user_id=user.user_id,
                        description=f"User has unused permission '{permission.name}' with no access in analysis period",
                        details={
                            'permission_id': perm_id,
                            'permission_name': permission.name,
                            'usage_count': usage_count,
                            'risk_level': permission.risk_level.value
                        },
                        detected_at=datetime.now(timezone.utc),
                        remediation_actions=[
                            "Review if permission is still needed",
                            "Remove permission if not required",
                            "Consider just-in-time access instead"
                        ]
                    )
                    violations.append(violation)
        
        return violations
    
    async def _detect_privilege_creep(self, user: UserAccess,
                                    access_history: List[Dict[str, Any]],
                                    permissions: Dict[str, Permission],
                                    roles: Dict[str, Role]) -> List[PrivilegeViolation]:
        """Detect privilege creep over time"""
        violations = []
        
        # Analyze permission grants over time
        permission_grants = []
        for event in access_history:
            if event.get('event_type') in ['permission_granted', 'role_assigned']:
                permission_grants.append({
                    'timestamp': datetime.fromisoformat(event['timestamp'].replace('Z', '+00:00')),
                    'permission_id': event.get('permission_id') or event.get('role_id'),
                    'event_type': event['event_type']
                })
        
        if len(permission_grants) < 3:
            return violations
        
        # Sort by timestamp
        permission_grants.sort(key=lambda x: x['timestamp'])
        
        # Detect rapid accumulation of privileges
        recent_grants = [g for g in permission_grants 
                        if (datetime.now(timezone.utc) - g['timestamp']).days <= 30]
        
        if len(recent_grants) >= 5:  # 5 or more grants in last 30 days
            high_risk_grants = []
            for grant in recent_grants:
                perm_id = grant['permission_id']
                permission = permissions.get(perm_id)
                if permission and permission.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
                    high_risk_grants.append(grant)
            
            if len(high_risk_grants) >= 2:
                violation = PrivilegeViolation(
                    violation_id=str(uuid.uuid4()),
                    violation_type="privilege_creep",
                    severity=RiskLevel.HIGH,
                    user_id=user.user_id,
                    description=f"Rapid privilege accumulation: {len(recent_grants)} grants in 30 days, {len(high_risk_grants)} high-risk",
                    details={
                        'recent_grants_count': len(recent_grants),
                        'high_risk_grants': len(high_risk_grants),
                        'grants': [{'permission_id': g['permission_id'], 'timestamp': g['timestamp'].isoformat()} for g in high_risk_grants]
                    },
                    detected_at=datetime.now(timezone.utc),
                    remediation_actions=[
                        "Review recent permission grants for business justification",
                        "Consider implementing approval workflows for high-risk permissions",
                        "Audit user's role changes and job responsibilities"
                    ]
                )
                violations.append(violation)
        
        return violations
    
    async def _detect_risky_privilege_combinations(self, user: UserAccess,
                                                 permissions: Dict[str, Permission],
                                                 roles: Dict[str, Role]) -> List[PrivilegeViolation]:
        """Detect risky combinations of privileges"""
        violations = []
        
        # Define risky combinations
        risky_combinations = [
            # Financial controls
            ([PrivilegeType.FINANCE, PrivilegeType.APPROVE], "Financial transaction and approval"),
            ([PrivilegeType.FINANCE, PrivilegeType.AUDIT], "Financial operations and audit"),
            
            # Security controls
            ([PrivilegeType.SECURITY, PrivilegeType.ADMIN], "Security and administrative access"),
            ([PrivilegeType.AUDIT, PrivilegeType.CONFIG], "Audit and system configuration"),
            
            # Data controls
            ([PrivilegeType.BACKUP, PrivilegeType.RESTORE, PrivilegeType.DELETE], "Full data lifecycle control"),
            ([PrivilegeType.HR, PrivilegeType.FINANCE], "HR and financial data access")
        ]
        
        user_privilege_types = set()
        for perm_id in user.effective_permissions:
            permission = permissions.get(perm_id)
            if permission:
                user_privilege_types.add(permission.privilege_type)
        
        for combination, description in risky_combinations:
            if all(priv_type in user_privilege_types for priv_type in combination):
                violation = PrivilegeViolation(
                    violation_id=str(uuid.uuid4()),
                    violation_type="risky_privilege_combination",
                    severity=RiskLevel.HIGH,
                    user_id=user.user_id,
                    description=f"User has risky privilege combination: {description}",
                    details={
                        'privilege_types': [pt.value for pt in combination],
                        'description': description
                    },
                    detected_at=datetime.now(timezone.utc),
                    remediation_actions=[
                        "Review business justification for this combination",
                        "Consider segregation of duties",
                        "Implement additional controls or monitoring"
                    ]
                )
                violations.append(violation)
        
        return violations


class RoleMiningEngine:
    """Role mining and optimization engine"""
    
    def __init__(self):
        self.similarity_threshold = 0.7
        self.min_users_for_role = 3
        
    async def mine_roles(self, users: List[UserAccess], 
                        permissions: Dict[str, Permission]) -> List[Role]:
        """Mine roles from user access patterns"""
        logging.info("Starting role mining process")
        
        # Create user-permission matrix
        user_permission_matrix = self._create_user_permission_matrix(users)
        
        # Cluster users based on permission similarity
        clusters = await self._cluster_users_by_permissions(user_permission_matrix)
        
        # Generate role candidates from clusters
        role_candidates = await self._generate_role_candidates(clusters, users, permissions)
        
        # Optimize and validate roles
        optimized_roles = await self._optimize_roles(role_candidates, users, permissions)
        
        logging.info(f"Role mining completed: {len(optimized_roles)} roles identified")
        return optimized_roles
    
    def _create_user_permission_matrix(self, users: List[UserAccess]) -> pd.DataFrame:
        """Create user-permission matrix for analysis"""
        # Get all unique permissions
        all_permissions = set()
        for user in users:
            all_permissions.update(user.effective_permissions)
        
        all_permissions = sorted(list(all_permissions))
        
        # Create matrix
        matrix_data = []
        user_ids = []
        
        for user in users:
            user_ids.append(user.user_id)
            row = [1 if perm in user.effective_permissions else 0 for perm in all_permissions]
            matrix_data.append(row)
        
        return pd.DataFrame(matrix_data, index=user_ids, columns=all_permissions)
    
    async def _cluster_users_by_permissions(self, user_permission_matrix: pd.DataFrame) -> List[List[str]]:
        """Cluster users based on permission similarity"""
        # Use hierarchical clustering with Jaccard distance
        from scipy.cluster.hierarchy import linkage, fcluster
        from scipy.spatial.distance import pdist
        
        # Calculate Jaccard distances
        distances = pdist(user_permission_matrix.values, metric='jaccard')
        
        # Perform hierarchical clustering
        linkage_matrix = linkage(distances, method='ward')
        
        # Form clusters
        cluster_labels = fcluster(linkage_matrix, t=1-self.similarity_threshold, criterion='distance')
        
        # Group users by cluster
        clusters = defaultdict(list)
        for i, user_id in enumerate(user_permission_matrix.index):
            clusters[cluster_labels[i]].append(user_id)
        
        # Filter clusters by minimum size
        valid_clusters = [cluster for cluster in clusters.values() 
                         if len(cluster) >= self.min_users_for_role]
        
        return valid_clusters
    
    async def _generate_role_candidates(self, clusters: List[List[str]], 
                                      users: List[UserAccess],
                                      permissions: Dict[str, Permission]) -> List[Role]:
        """Generate role candidates from user clusters"""
        role_candidates = []
        user_lookup = {user.user_id: user for user in users}
        
        for i, cluster in enumerate(clusters):
            # Find common permissions among cluster users
            common_permissions = None
            cluster_users = [user_lookup[user_id] for user_id in cluster if user_id in user_lookup]
            
            for user in cluster_users:
                user_perms = set(user.effective_permissions)
                if common_permissions is None:
                    common_permissions = user_perms
                else:
                    common_permissions &= user_perms
            
            if common_permissions and len(common_permissions) >= 3:
                # Generate role name based on cluster characteristics
                role_name = self._generate_role_name(cluster_users, common_permissions, permissions)
                
                role_candidate = Role(
                    role_id=f"mined_role_{i+1}",
                    name=role_name,
                    description=f"Role mined from {len(cluster_users)} users with {len(common_permissions)} common permissions",
                    permissions=list(common_permissions),
                    risk_level=self._calculate_role_risk_level(common_permissions, permissions)
                )
                
                role_candidates.append(role_candidate)
        
        return role_candidates
    
    def _generate_role_name(self, users: List[UserAccess], 
                          permissions: List[str],
                          permission_objects: Dict[str, Permission]) -> str:
        """Generate a meaningful role name"""
        # Analyze user departments and job titles
        departments = [user.department for user in users if user.department]
        job_titles = [user.job_title for user in users if user.job_title]
        
        # Most common department
        dept_counter = Counter(departments)
        common_dept = dept_counter.most_common(1)[0][0] if dept_counter else "General"
        
        # Analyze permission types
        privilege_types = []
        for perm_id in permissions:
            permission = permission_objects.get(perm_id)
            if permission:
                privilege_types.append(permission.privilege_type.value)
        
        type_counter = Counter(privilege_types)
        common_type = type_counter.most_common(1)[0][0] if type_counter else "Access"
        
        return f"{common_dept}_{common_type.title()}_Role"
    
    def _calculate_role_risk_level(self, permissions: List[str], 
                                 permission_objects: Dict[str, Permission]) -> RiskLevel:
        """Calculate risk level for mined role"""
        risk_scores = []
        
        for perm_id in permissions:
            permission = permission_objects.get(perm_id)
            if permission:
                risk_map = {
                    RiskLevel.CRITICAL: 5,
                    RiskLevel.HIGH: 4,
                    RiskLevel.MEDIUM: 3,
                    RiskLevel.LOW: 2,
                    RiskLevel.MINIMAL: 1
                }
                risk_scores.append(risk_map.get(permission.risk_level, 3))
        
        if not risk_scores:
            return RiskLevel.MEDIUM
        
        avg_risk = statistics.mean(risk_scores)
        
        if avg_risk >= 4.5:
            return RiskLevel.CRITICAL
        elif avg_risk >= 3.5:
            return RiskLevel.HIGH
        elif avg_risk >= 2.5:
            return RiskLevel.MEDIUM
        elif avg_risk >= 1.5:
            return RiskLevel.LOW
        else:
            return RiskLevel.MINIMAL
    
    async def _optimize_roles(self, role_candidates: List[Role], 
                            users: List[UserAccess],
                            permissions: Dict[str, Permission]) -> List[Role]:
        """Optimize roles by removing redundancy and improving coverage"""
        optimized_roles = []
        
        # Remove duplicate roles (same permission sets)
        unique_roles = []
        seen_permission_sets = set()
        
        for role in role_candidates:
            perm_set = frozenset(role.permissions)
            if perm_set not in seen_permission_sets:
                unique_roles.append(role)
                seen_permission_sets.add(perm_set)
        
        # Merge similar roles
        merged_roles = await self._merge_similar_roles(unique_roles, permissions)
        
        # Validate role utility
        for role in merged_roles:
            if await self._validate_role_utility(role, users):
                optimized_roles.append(role)
        
        return optimized_roles
    
    async def _merge_similar_roles(self, roles: List[Role], 
                                 permissions: Dict[str, Permission]) -> List[Role]:
        """Merge roles with high permission overlap"""
        merged_roles = []
        processed_roles = set()
        
        for i, role1 in enumerate(roles):
            if i in processed_roles:
                continue
            
            current_role = role1
            
            for j, role2 in enumerate(roles[i+1:], i+1):
                if j in processed_roles:
                    continue
                
                # Calculate permission overlap
                perms1 = set(role1.permissions)
                perms2 = set(role2.permissions)
                
                overlap = len(perms1 & perms2)
                union = len(perms1 | perms2)
                
                similarity = overlap / union if union > 0 else 0
                
                if similarity >= 0.8:  # High similarity
                    # Merge roles
                    merged_permissions = list(perms1 | perms2)
                    current_role = Role(
                        role_id=f"merged_{role1.role_id}_{role2.role_id}",
                        name=f"Merged_{role1.name}_{role2.name}",
                        description=f"Merged role from {role1.name} and {role2.name}",
                        permissions=merged_permissions,
                        risk_level=max(role1.risk_level, role2.risk_level, key=lambda x: ['minimal', 'low', 'medium', 'high', 'critical'].index(x.value))
                    )
                    processed_roles.add(j)
            
            merged_roles.append(current_role)
            processed_roles.add(i)
        
        return merged_roles
    
    async def _validate_role_utility(self, role: Role, users: List[UserAccess]) -> bool:
        """Validate that a role would be useful"""
        # Count how many users would benefit from this role
        potential_users = 0
        
        role_perms = set(role.permissions)
        
        for user in users:
            user_perms = set(user.effective_permissions)
            
            # If user has all role permissions plus some others, they could use this role
            if role_perms.issubset(user_perms):
                potential_users += 1
        
        # Role is useful if at least 3 users would benefit
        return potential_users >= 3


class SoDAnalyzer:
    """Segregation of Duties analyzer"""
    
    def __init__(self):
        self.default_sod_rules = self._create_default_sod_rules()
    
    def _create_default_sod_rules(self) -> List[SoDRule]:
        """Create default SoD rules based on common compliance requirements"""
        rules = []
        
        # Financial controls
        rules.append(SoDRule(
            rule_id="sod_financial_01",
            name="Financial Transaction and Approval Segregation",
            description="Users who can create financial transactions should not be able to approve them",
            violation_type=SoDViolationType.FINANCIAL_CONTROL,
            conflicting_permissions=[
                ["finance_create_transaction", "finance_approve_transaction"],
                ["finance_payment_create", "finance_payment_approve"]
            ],
            conflicting_roles=[],
            severity=RiskLevel.CRITICAL,
            regulatory_basis="SOX Section 404, PCI-DSS",
            business_justification="Prevents fraud and ensures proper financial controls"
        ))
        
        # Security administration
        rules.append(SoDRule(
            rule_id="sod_security_01",
            name="Security Administration and Audit Segregation",
            description="Security administrators should not have audit/compliance access",
            violation_type=SoDViolationType.SECURITY_ADMIN,
            conflicting_permissions=[
                ["security_admin", "audit_review"],
                ["security_config", "compliance_audit"]
            ],
            conflicting_roles=[
                ["SecurityAdmin", "AuditManager"]
            ],
            severity=RiskLevel.HIGH,
            regulatory_basis="ISO 27001, NIST Framework",
            business_justification="Ensures independent security oversight"
        ))
        
        # HR and Payroll
        rules.append(SoDRule(
            rule_id="sod_hr_01",
            name="HR Management and Payroll Segregation",
            description="HR personnel managing employee data should not process payroll",
            violation_type=SoDViolationType.HR_PAYROLL,
            conflicting_permissions=[
                ["hr_employee_manage", "payroll_process"],
                ["hr_salary_set", "payroll_calculate"]
            ],
            conflicting_roles=[],
            severity=RiskLevel.HIGH,
            regulatory_basis="SOX, Labor regulations",
            business_justification="Prevents payroll fraud and ensures proper controls"
        ))
        
        # IT Operations
        rules.append(SoDRule(
            rule_id="sod_it_01",
            name="System Development and Production Access Segregation",
            description="Developers should not have production system access",
            violation_type=SoDViolationType.IT_OPERATIONS,
            conflicting_permissions=[
                ["system_develop", "production_access"],
                ["code_deploy", "production_admin"]
            ],
            conflicting_roles=[
                ["Developer", "ProductionAdmin"]
            ],
            severity=RiskLevel.MEDIUM,
            regulatory_basis="ITIL, Change Management best practices",
            business_justification="Ensures proper change control and system integrity"
        ))
        
        return rules
    
    async def analyze_sod_violations(self, users: List[UserAccess],
                                   permissions: Dict[str, Permission],
                                   roles: Dict[str, Role],
                                   custom_rules: List[SoDRule] = None) -> List[PrivilegeViolation]:
        """Analyze users for SoD violations"""
        violations = []
        
        # Combine default and custom rules
        all_rules = self.default_sod_rules.copy()
        if custom_rules:
            all_rules.extend(custom_rules)
        
        for user in users:
            for rule in all_rules:
                if not rule.active:
                    continue
                
                # Check if user is in exceptions list
                if user.user_id in rule.exceptions:
                    continue
                
                # Check permission-based conflicts
                for conflicting_group in rule.conflicting_permissions:
                    user_has_conflict = all(perm_id in user.effective_permissions 
                                          for perm_id in conflicting_group)
                    
                    if user_has_conflict:
                        violation = PrivilegeViolation(
                            violation_id=str(uuid.uuid4()),
                            violation_type="sod_violation_permissions",
                            severity=rule.severity,
                            user_id=user.user_id,
                            description=f"SoD violation: {rule.name}",
                            details={
                                'rule_id': rule.rule_id,
                                'rule_name': rule.name,
                                'conflicting_permissions': conflicting_group,
                                'regulatory_basis': rule.regulatory_basis,
                                'violation_type': rule.violation_type.value
                            },
                            detected_at=datetime.now(timezone.utc),
                            remediation_actions=[
                                "Remove one of the conflicting permissions",
                                "Implement compensating controls",
                                "Obtain formal exception approval",
                                "Consider role-based access redesign"
                            ],
                            compliance_impact=f"Violates {rule.regulatory_basis}" if rule.regulatory_basis else None
                        )
                        violations.append(violation)
                
                # Check role-based conflicts
                for conflicting_group in rule.conflicting_roles:
                    user_has_conflict = all(role_id in user.roles 
                                          for role_id in conflicting_group)
                    
                    if user_has_conflict:
                        violation = PrivilegeViolation(
                            violation_id=str(uuid.uuid4()),
                            violation_type="sod_violation_roles",
                            severity=rule.severity,
                            user_id=user.user_id,
                            description=f"SoD violation: {rule.name} (Role-based)",
                            details={
                                'rule_id': rule.rule_id,
                                'rule_name': rule.name,
                                'conflicting_roles': conflicting_group,
                                'regulatory_basis': rule.regulatory_basis,
                                'violation_type': rule.violation_type.value
                            },
                            detected_at=datetime.now(timezone.utc),
                            remediation_actions=[
                                "Remove one of the conflicting roles",
                                "Redesign role structure",
                                "Implement compensating controls",
                                "Obtain formal exception approval"
                            ],
                            compliance_impact=f"Violates {rule.regulatory_basis}" if rule.regulatory_basis else None
                        )
                        violations.append(violation)
        
        return violations


class AccessCertificationEngine:
    """Access certification campaign management"""
    
    def __init__(self, db_path: str):
        self.db_path = db_path
        
    async def create_certification_campaign(self, campaign: AccessCertificationCampaign,
                                          users: List[UserAccess],
                                          roles: Dict[str, Role]) -> bool:
        """Create new access certification campaign"""
        try:
            # Generate certification tasks based on scope
            certification_tasks = await self._generate_certification_tasks(campaign, users, roles)
            
            # Store campaign and tasks
            await self._store_campaign(campaign, certification_tasks)
            
            # Send notifications to certifiers
            await self._notify_certifiers(campaign, certification_tasks)
            
            logging.info(f"Created certification campaign '{campaign.name}' with {len(certification_tasks)} tasks")
            return True
            
        except Exception as e:
            logging.error(f"Failed to create certification campaign: {e}")
            return False
    
    async def _generate_certification_tasks(self, campaign: AccessCertificationCampaign,
                                          users: List[UserAccess],
                                          roles: Dict[str, Role]) -> List[Dict[str, Any]]:
        """Generate certification tasks based on campaign scope"""
        tasks = []
        
        scope = campaign.scope
        
        # Filter users based on scope
        target_users = []
        
        if scope.get('all_users'):
            target_users = users
        else:
            if scope.get('departments'):
                dept_users = [u for u in users if u.department in scope['departments']]
                target_users.extend(dept_users)
            
            if scope.get('roles'):
                role_users = [u for u in users if any(r in scope['roles'] for r in u.roles)]
                target_users.extend(role_users)
            
            if scope.get('users'):
                specific_users = [u for u in users if u.user_id in scope['users']]
                target_users.extend(specific_users)
        
        # Remove duplicates
        target_users = list({u.user_id: u for u in target_users}.values())
        
        # Generate tasks for each user
        for user in target_users:
            # Calculate risk score for prioritization
            risk_score = await self._calculate_certification_risk_score(user, roles)
            
            # Determine certifier (manager or designated certifier)
            certifier = user.manager if user.manager in campaign.certifiers else campaign.certifiers[0]
            
            task = {
                'task_id': str(uuid.uuid4()),
                'campaign_id': campaign.campaign_id,
                'user_id': user.user_id,
                'certifier_id': certifier,
                'risk_score': risk_score,
                'auto_approve': risk_score <= campaign.auto_approve_threshold,
                'due_date': campaign.end_date,
                'status': 'pending',
                'user_data': {
                    'username': user.username,
                    'email': user.email,
                    'department': user.department,
                    'job_title': user.job_title,
                    'roles': user.roles,
                    'direct_permissions': user.direct_permissions,
                    'last_access': user.last_access.isoformat() if user.last_access else None
                },
                'created_at': datetime.now(timezone.utc)
            }
            
            tasks.append(task)
        
        return tasks
    
    async def _calculate_certification_risk_score(self, user: UserAccess, 
                                                roles: Dict[str, Role]) -> float:
        """Calculate risk score for certification prioritization"""
        risk_factors = []
        
        # Role-based risk
        for role_id in user.roles:
            role = roles.get(role_id)
            if role:
                role_risk_map = {
                    RiskLevel.CRITICAL: 1.0,
                    RiskLevel.HIGH: 0.8,
                    RiskLevel.MEDIUM: 0.5,
                    RiskLevel.LOW: 0.3,
                    RiskLevel.MINIMAL: 0.1
                }
                risk_factors.append(role_risk_map.get(role.risk_level, 0.5))
        
        # Time since last certification
        if user.last_certification:
            days_since_cert = (datetime.now(timezone.utc) - user.last_certification).days
            if days_since_cert > 180:  # 6 months
                risk_factors.append(0.8)
            elif days_since_cert > 90:  # 3 months
                risk_factors.append(0.5)
        else:
            risk_factors.append(0.9)  # Never certified
        
        # Access frequency
        if user.last_access:
            days_since_access = (datetime.now(timezone.utc) - user.last_access).days
            if days_since_access > 90:  # Inactive users higher risk
                risk_factors.append(0.7)
        
        # Direct permissions (bypass roles)
        if user.direct_permissions:
            risk_factors.append(0.6)
        
        return min(1.0, statistics.mean(risk_factors)) if risk_factors else 0.5
    
    async def _store_campaign(self, campaign: AccessCertificationCampaign, 
                            tasks: List[Dict[str, Any]]):
        """Store campaign and tasks in database"""
        async with aiosqlite.connect(self.db_path) as db:
            # Store campaign
            await db.execute("""
                INSERT INTO certification_campaigns (
                    campaign_id, name, description, scope, start_date, end_date,
                    certifiers, status, auto_approve_threshold, escalation_threshold_days,
                    created_by, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                campaign.campaign_id, campaign.name, campaign.description,
                json.dumps(campaign.scope), campaign.start_date.isoformat(),
                campaign.end_date.isoformat(), json.dumps(campaign.certifiers),
                campaign.status, campaign.auto_approve_threshold,
                campaign.escalation_threshold_days, campaign.created_by,
                campaign.created_at.isoformat(), campaign.updated_at.isoformat()
            ))
            
            # Store tasks
            for task in tasks:
                await db.execute("""
                    INSERT INTO certification_tasks (
                        task_id, campaign_id, user_id, certifier_id, risk_score,
                        auto_approve, due_date, status, user_data, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    task['task_id'], task['campaign_id'], task['user_id'],
                    task['certifier_id'], task['risk_score'], task['auto_approve'],
                    task['due_date'].isoformat(), task['status'],
                    json.dumps(task['user_data']), task['created_at'].isoformat()
                ))
            
            await db.commit()
    
    async def _notify_certifiers(self, campaign: AccessCertificationCampaign, 
                               tasks: List[Dict[str, Any]]):
        """Send notifications to certifiers"""
        # Group tasks by certifier
        certifier_tasks = defaultdict(list)
        for task in tasks:
            certifier_tasks[task['certifier_id']].append(task)
        
        # Send notifications (this would integrate with email/notification system)
        for certifier_id, certifier_task_list in certifier_tasks.items():
            high_risk_count = sum(1 for task in certifier_task_list if task['risk_score'] > 0.7)
            
            notification = {
                'recipient': certifier_id,
                'subject': f"Access Certification Required: {campaign.name}",
                'message': f"You have {len(certifier_task_list)} access certifications to complete. "
                          f"{high_risk_count} are high-risk and require immediate attention.",
                'campaign_id': campaign.campaign_id,
                'due_date': campaign.end_date.isoformat(),
                'tasks': certifier_task_list
            }
            
            # In production, this would send actual notifications
            logging.info(f"Notification queued for certifier {certifier_id}: {len(certifier_task_list)} tasks")


class PrivilegeAccessIntelligence:
    """Main privilege and access intelligence orchestrator"""
    
    def __init__(self, db_path: str = "privilege_intelligence.db", 
                 redis_url: str = "redis://localhost:6379"):
        self.db_path = db_path
        self.redis_url = redis_url
        self.redis_client = None
        
        # Initialize components
        self.privilege_analyzer = PrivilegeAnalyzer()
        self.role_mining_engine = RoleMiningEngine()
        self.sod_analyzer = SoDAnalyzer()
        self.certification_engine = AccessCertificationEngine(db_path)
        
        # In-memory caches
        self.permissions = {}
        self.roles = {}
        self.users = {}
        self.sod_rules = []
        
        # Statistics
        self.stats = {
            'violations_detected': 0,
            'roles_mined': 0,
            'certifications_completed': 0,
            'sod_violations': 0,
            'start_time': datetime.now(timezone.utc)
        }
        
        self.initialized = False
        logging.info("Privilege Access Intelligence system initialized")
    
    async def initialize(self):
        """Initialize the intelligence system"""
        if self.initialized:
            return
        
        # Initialize database
        await self._initialize_database()
        
        # Initialize Redis
        try:
            self.redis_client = redis.from_url(self.redis_url)
            await self.redis_client.ping()
            self.privilege_analyzer.redis_client = self.redis_client
            logging.info("Redis connection established")
        except Exception as e:
            logging.warning(f"Redis connection failed: {e}")
        
        # Load existing data
        await self._load_data()
        
        self.initialized = True
        logging.info("Privilege Access Intelligence system fully initialized")
    
    async def analyze_privileges(self, access_history: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
        """Comprehensive privilege analysis"""
        if not self.initialized:
            await self.initialize()
        
        analysis_results = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'excessive_privileges': [],
            'unused_permissions': [],
            'sod_violations': [],
            'role_recommendations': [],
            'certification_recommendations': [],
            'summary': {}
        }
        
        users_list = list(self.users.values())
        
        # Analyze excessive privileges
        try:
            excessive_violations = await self.privilege_analyzer.analyze_excessive_privileges(
                users_list, self.permissions, self.roles, access_history
            )
            analysis_results['excessive_privileges'] = [asdict(v) for v in excessive_violations]
            self.stats['violations_detected'] += len(excessive_violations)
        except Exception as e:
            logging.error(f"Excessive privilege analysis failed: {e}")
        
        # Analyze SoD violations
        try:
            sod_violations = await self.sod_analyzer.analyze_sod_violations(
                users_list, self.permissions, self.roles, self.sod_rules
            )
            analysis_results['sod_violations'] = [asdict(v) for v in sod_violations]
            self.stats['sod_violations'] += len(sod_violations)
        except Exception as e:
            logging.error(f"SoD analysis failed: {e}")
        
        # Generate role mining recommendations
        try:
            mined_roles = await self.role_mining_engine.mine_roles(users_list, self.permissions)
            analysis_results['role_recommendations'] = [asdict(r) for r in mined_roles]
            self.stats['roles_mined'] += len(mined_roles)
        except Exception as e:
            logging.error(f"Role mining failed: {e}")
        
        # Generate certification recommendations
        cert_recommendations = await self._generate_certification_recommendations(users_list)
        analysis_results['certification_recommendations'] = cert_recommendations
        
        # Generate summary
        analysis_results['summary'] = {
            'total_users_analyzed': len(users_list),
            'excessive_privilege_violations': len(analysis_results['excessive_privileges']),
            'sod_violations_found': len(analysis_results['sod_violations']),
            'roles_recommended': len(analysis_results['role_recommendations']),
            'users_requiring_certification': len(cert_recommendations),
            'high_risk_users': len([u for u in users_list if u.risk_score >= 70]),
            'analysis_time': datetime.now(timezone.utc).isoformat()
        }
        
        # Store analysis results
        await self._store_analysis_results(analysis_results)
        
        return analysis_results
    
    async def create_access_certification_campaign(self, campaign_config: Dict[str, Any]) -> bool:
        """Create access certification campaign"""
        try:
            campaign = AccessCertificationCampaign(
                campaign_id=str(uuid.uuid4()),
                name=campaign_config['name'],
                description=campaign_config['description'],
                scope=campaign_config['scope'],
                start_date=datetime.now(timezone.utc),
                end_date=datetime.fromisoformat(campaign_config['end_date']),
                certifiers=campaign_config['certifiers'],
                auto_approve_threshold=campaign_config.get('auto_approve_threshold', 0.1),
                escalation_threshold_days=campaign_config.get('escalation_threshold_days', 7),
                created_by=campaign_config.get('created_by', 'system')
            )
            
            success = await self.certification_engine.create_certification_campaign(
                campaign, list(self.users.values()), self.roles
            )
            
            if success:
                self.stats['certifications_completed'] += 1
            
            return success
            
        except Exception as e:
            logging.error(f"Failed to create certification campaign: {e}")
            return False
    
    async def get_user_access_summary(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Get comprehensive access summary for a user"""
        user = self.users.get(user_id)
        if not user:
            return None
        
        # Get user's effective permissions with details
        effective_perms = []
        for perm_id in user.effective_permissions:
            permission = self.permissions.get(perm_id)
            if permission:
                effective_perms.append({
                    'permission_id': perm_id,
                    'name': permission.name,
                    'privilege_type': permission.privilege_type.value,
                    'risk_level': permission.risk_level.value,
                    'resource_type': permission.resource_type
                })
        
        # Get user's roles with details
        user_roles = []
        for role_id in user.roles:
            role = self.roles.get(role_id)
            if role:
                user_roles.append({
                    'role_id': role_id,
                    'name': role.name,
                    'risk_level': role.risk_level.value,
                    'permission_count': len(role.permissions),
                    'last_certified': role.last_certified.isoformat() if role.last_certified else None
                })
        
        return {
            'user_id': user_id,
            'username': user.username,
            'email': user.email,
            'department': user.department,
            'job_title': user.job_title,
            'manager': user.manager,
            'risk_score': user.risk_score,
            'compliance_status': user.compliance_status,
            'last_access': user.last_access.isoformat() if user.last_access else None,
            'last_certification': user.last_certification.isoformat() if user.last_certification else None,
            'roles': user_roles,
            'effective_permissions': effective_perms,
            'total_permissions': len(effective_perms),
            'high_risk_permissions': len([p for p in effective_perms if p['risk_level'] in ['high', 'critical']]),
            'direct_permissions': len(user.direct_permissions)
        }
    
    async def get_system_statistics(self) -> Dict[str, Any]:
        """Get comprehensive system statistics"""
        uptime = datetime.now(timezone.utc) - self.stats['start_time']
        
        # Calculate additional statistics
        high_risk_users = len([u for u in self.users.values() if u.risk_score >= 70])
        critical_permissions = len([p for p in self.permissions.values() if p.risk_level == RiskLevel.CRITICAL])
        
        # Role statistics
        role_stats = {
            'total_roles': len(self.roles),
            'high_risk_roles': len([r for r in self.roles.values() if r.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]]),
            'roles_requiring_certification': len([r for r in self.roles.values() if r.certification_required])
        }
        
        return {
            'system_uptime_seconds': uptime.total_seconds(),
            'total_users': len(self.users),
            'total_permissions': len(self.permissions),
            'total_roles': len(self.roles),
            'high_risk_users': high_risk_users,
            'critical_permissions': critical_permissions,
            'violations_detected': self.stats['violations_detected'],
            'sod_violations': self.stats['sod_violations'],
            'roles_mined': self.stats['roles_mined'],
            'certifications_completed': self.stats['certifications_completed'],
            'role_statistics': role_stats,
            'last_analysis': datetime.now(timezone.utc).isoformat()
        }
    
    async def _generate_certification_recommendations(self, users: List[UserAccess]) -> List[Dict[str, Any]]:
        """Generate certification recommendations"""
        recommendations = []
        
        for user in users:
            needs_certification = False
            reasons = []
            
            # Check if certification is overdue
            if user.last_certification:
                days_since_cert = (datetime.now(timezone.utc) - user.last_certification).days
                if days_since_cert > 90:
                    needs_certification = True
                    reasons.append(f"Last certified {days_since_cert} days ago")
            else:
                needs_certification = True
                reasons.append("Never certified")
            
            # Check for high-risk access
            if user.risk_score >= 70:
                needs_certification = True
                reasons.append(f"High risk score: {user.risk_score}")
            
            # Check for direct permissions
            if user.direct_permissions:
                needs_certification = True
                reasons.append(f"Has {len(user.direct_permissions)} direct permissions")
            
            if needs_certification:
                recommendations.append({
                    'user_id': user.user_id,
                    'username': user.username,
                    'priority': 'high' if user.risk_score >= 80 else 'medium',
                    'reasons': reasons,
                    'recommended_certifier': user.manager or 'SecurityTeam'
                })
        
        return recommendations
    
    async def _initialize_database(self):
        """Initialize database schema"""
        async with aiosqlite.connect(self.db_path) as db:
            # Permissions table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS permissions (
                    permission_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT,
                    privilege_type TEXT NOT NULL,
                    resource_type TEXT NOT NULL,
                    resource_identifier TEXT,
                    risk_level TEXT DEFAULT 'medium',
                    business_justification TEXT,
                    regulatory_requirement TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    last_modified TEXT DEFAULT CURRENT_TIMESTAMP,
                    active BOOLEAN DEFAULT 1
                )
            """)
            
            # Roles table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS roles (
                    role_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT,
                    permissions TEXT,
                    parent_roles TEXT,
                    child_roles TEXT,
                    risk_level TEXT DEFAULT 'medium',
                    business_owner TEXT,
                    technical_owner TEXT,
                    certification_required BOOLEAN DEFAULT 0,
                    certification_frequency_days INTEGER DEFAULT 90,
                    last_certified TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    last_modified TEXT DEFAULT CURRENT_TIMESTAMP,
                    active BOOLEAN DEFAULT 1,
                    metadata TEXT
                )
            """)
            
            # Users table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS user_access (
                    user_id TEXT PRIMARY KEY,
                    username TEXT NOT NULL,
                    email TEXT,
                    department TEXT,
                    job_title TEXT,
                    manager TEXT,
                    roles TEXT,
                    direct_permissions TEXT,
                    effective_permissions TEXT,
                    last_access TEXT,
                    access_frequency TEXT,
                    risk_score REAL DEFAULT 0.0,
                    compliance_status TEXT DEFAULT 'compliant',
                    certification_status TEXT DEFAULT 'pending',
                    last_certification TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    active BOOLEAN DEFAULT 1
                )
            """)
            
            # Violations table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS privilege_violations (
                    violation_id TEXT PRIMARY KEY,
                    violation_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    description TEXT NOT NULL,
                    details TEXT,
                    detected_at TEXT NOT NULL,
                    resolved BOOLEAN DEFAULT 0,
                    resolved_at TEXT,
                    false_positive BOOLEAN DEFAULT 0,
                    remediation_actions TEXT,
                    business_impact TEXT,
                    compliance_impact TEXT
                )
            """)
            
            # SoD Rules table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS sod_rules (
                    rule_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT NOT NULL,
                    violation_type TEXT NOT NULL,
                    conflicting_permissions TEXT,
                    conflicting_roles TEXT,
                    severity TEXT DEFAULT 'high',
                    regulatory_basis TEXT,
                    business_justification TEXT,
                    exceptions TEXT,
                    active BOOLEAN DEFAULT 1,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Certification campaigns table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS certification_campaigns (
                    campaign_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT,
                    scope TEXT,
                    start_date TEXT NOT NULL,
                    end_date TEXT NOT NULL,
                    certifiers TEXT,
                    status TEXT DEFAULT 'active',
                    completion_rate REAL DEFAULT 0.0,
                    violations_found INTEGER DEFAULT 0,
                    auto_approve_threshold REAL DEFAULT 0.1,
                    escalation_threshold_days INTEGER DEFAULT 7,
                    created_by TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Certification tasks table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS certification_tasks (
                    task_id TEXT PRIMARY KEY,
                    campaign_id TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    certifier_id TEXT NOT NULL,
                    risk_score REAL NOT NULL,
                    auto_approve BOOLEAN DEFAULT 0,
                    due_date TEXT NOT NULL,
                    status TEXT DEFAULT 'pending',
                    user_data TEXT,
                    decision TEXT,
                    decision_reason TEXT,
                    decided_at TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (campaign_id) REFERENCES certification_campaigns (campaign_id)
                )
            """)
            
            # Analysis results table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS analysis_results (
                    analysis_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    results TEXT NOT NULL,
                    summary TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Create indexes
            indexes = [
                "CREATE INDEX IF NOT EXISTS idx_violations_user ON privilege_violations(user_id)",
                "CREATE INDEX IF NOT EXISTS idx_violations_type ON privilege_violations(violation_type)",
                "CREATE INDEX IF NOT EXISTS idx_violations_severity ON privilege_violations(severity)",
                "CREATE INDEX IF NOT EXISTS idx_tasks_campaign ON certification_tasks(campaign_id)",
                "CREATE INDEX IF NOT EXISTS idx_tasks_certifier ON certification_tasks(certifier_id)",
                "CREATE INDEX IF NOT EXISTS idx_tasks_status ON certification_tasks(status)"
            ]
            
            for index_sql in indexes:
                await db.execute(index_sql)
            
            await db.commit()
        
        logging.info("Privilege Access Intelligence database initialized")
    
    async def _load_data(self):
        """Load existing data from database"""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                # Load permissions
                async with db.execute("SELECT * FROM permissions WHERE active = 1") as cursor:
                    rows = await cursor.fetchall()
                    columns = [description[0] for description in cursor.description]
                    
                    for row in rows:
                        row_dict = dict(zip(columns, row))
                        permission = Permission(
                            permission_id=row_dict['permission_id'],
                            name=row_dict['name'],
                            description=row_dict['description'] or '',
                            privilege_type=PrivilegeType(row_dict['privilege_type']),
                            resource_type=row_dict['resource_type'],
                            resource_identifier=row_dict['resource_identifier'],
                            risk_level=RiskLevel(row_dict['risk_level']),
                            business_justification=row_dict['business_justification'],
                            regulatory_requirement=row_dict['regulatory_requirement'],
                            created_at=datetime.fromisoformat(row_dict['created_at']),
                            last_modified=datetime.fromisoformat(row_dict['last_modified']),
                            active=bool(row_dict['active'])
                        )
                        self.permissions[permission.permission_id] = permission
                
                # Load roles
                async with db.execute("SELECT * FROM roles WHERE active = 1") as cursor:
                    rows = await cursor.fetchall()
                    columns = [description[0] for description in cursor.description]
                    
                    for row in rows:
                        row_dict = dict(zip(columns, row))
                        role = Role(
                            role_id=row_dict['role_id'],
                            name=row_dict['name'],
                            description=row_dict['description'] or '',
                            permissions=json.loads(row_dict['permissions']) if row_dict['permissions'] else [],
                            parent_roles=json.loads(row_dict['parent_roles']) if row_dict['parent_roles'] else [],
                            child_roles=json.loads(row_dict['child_roles']) if row_dict['child_roles'] else [],
                            risk_level=RiskLevel(row_dict['risk_level']),
                            business_owner=row_dict['business_owner'],
                            technical_owner=row_dict['technical_owner'],
                            certification_required=bool(row_dict['certification_required']),
                            certification_frequency_days=row_dict['certification_frequency_days'],
                            last_certified=datetime.fromisoformat(row_dict['last_certified']) if row_dict['last_certified'] else None,
                            created_at=datetime.fromisoformat(row_dict['created_at']),
                            last_modified=datetime.fromisoformat(row_dict['last_modified']),
                            active=bool(row_dict['active']),
                            metadata=json.loads(row_dict['metadata']) if row_dict['metadata'] else {}
                        )
                        self.roles[role.role_id] = role
                
                # Load users
                async with db.execute("SELECT * FROM user_access WHERE active = 1") as cursor:
                    rows = await cursor.fetchall()
                    columns = [description[0] for description in cursor.description]
                    
                    for row in rows:
                        row_dict = dict(zip(columns, row))
                        user = UserAccess(
                            user_id=row_dict['user_id'],
                            username=row_dict['username'],
                            email=row_dict['email'],
                            department=row_dict['department'],
                            job_title=row_dict['job_title'],
                            manager=row_dict['manager'],
                            roles=json.loads(row_dict['roles']) if row_dict['roles'] else [],
                            direct_permissions=json.loads(row_dict['direct_permissions']) if row_dict['direct_permissions'] else [],
                            effective_permissions=json.loads(row_dict['effective_permissions']) if row_dict['effective_permissions'] else [],
                            last_access=datetime.fromisoformat(row_dict['last_access']) if row_dict['last_access'] else None,
                            access_frequency=json.loads(row_dict['access_frequency']) if row_dict['access_frequency'] else {},
                            risk_score=row_dict['risk_score'],
                            compliance_status=row_dict['compliance_status'],
                            certification_status=row_dict['certification_status'],
                            last_certification=datetime.fromisoformat(row_dict['last_certification']) if row_dict['last_certification'] else None,
                            created_at=datetime.fromisoformat(row_dict['created_at']),
                            updated_at=datetime.fromisoformat(row_dict['updated_at']),
                            active=bool(row_dict['active'])
                        )
                        self.users[user.user_id] = user
                
                # Load SoD rules
                async with db.execute("SELECT * FROM sod_rules WHERE active = 1") as cursor:
                    rows = await cursor.fetchall()
                    columns = [description[0] for description in cursor.description]
                    
                    for row in rows:
                        row_dict = dict(zip(columns, row))
                        rule = SoDRule(
                            rule_id=row_dict['rule_id'],
                            name=row_dict['name'],
                            description=row_dict['description'],
                            violation_type=SoDViolationType(row_dict['violation_type']),
                            conflicting_permissions=json.loads(row_dict['conflicting_permissions']) if row_dict['conflicting_permissions'] else [],
                            conflicting_roles=json.loads(row_dict['conflicting_roles']) if row_dict['conflicting_roles'] else [],
                            severity=RiskLevel(row_dict['severity']),
                            regulatory_basis=row_dict['regulatory_basis'],
                            business_justification=row_dict['business_justification'] or '',
                            exceptions=json.loads(row_dict['exceptions']) if row_dict['exceptions'] else [],
                            active=bool(row_dict['active']),
                            created_at=datetime.fromisoformat(row_dict['created_at'])
                        )
                        self.sod_rules.append(rule)
            
            logging.info(f"Loaded data: {len(self.permissions)} permissions, {len(self.roles)} roles, {len(self.users)} users, {len(self.sod_rules)} SoD rules")
            
        except Exception as e:
            logging.error(f"Failed to load data: {e}")
    
    async def _store_analysis_results(self, results: Dict[str, Any]):
        """Store analysis results"""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute("""
                    INSERT INTO analysis_results (
                        analysis_id, timestamp, results, summary
                    ) VALUES (?, ?, ?, ?)
                """, (
                    str(uuid.uuid4()),
                    results['timestamp'],
                    json.dumps(results),
                    json.dumps(results['summary'])
                ))
                await db.commit()
        except Exception as e:
            logging.error(f"Failed to store analysis results: {e}")
    
    async def shutdown(self):
        """Gracefully shutdown the system"""
        logging.info("Shutting down Privilege Access Intelligence system")
        
        if self.redis_client:
            await self.redis_client.close()
        
        logging.info("Privilege Access Intelligence system shutdown complete")


# Example usage and testing
async def example_usage():
    """Example usage of the Privilege Access Intelligence system"""
    
    # Initialize system
    intelligence = PrivilegeAccessIntelligence(
        db_path="test_privilege_intelligence.db",
        redis_url="redis://localhost:6379"
    )
    
    await intelligence.initialize()
    
    # Create sample permissions
    sample_permissions = [
        Permission(
            permission_id="perm_001",
            name="Financial Transaction Create",
            description="Create financial transactions",
            privilege_type=PrivilegeType.FINANCE,
            resource_type="financial_system",
            risk_level=RiskLevel.HIGH
        ),
        Permission(
            permission_id="perm_002",
            name="Financial Transaction Approve",
            description="Approve financial transactions",
            privilege_type=PrivilegeType.APPROVE,
            resource_type="financial_system",
            risk_level=RiskLevel.CRITICAL
        ),
        Permission(
            permission_id="perm_003",
            name="HR Employee Data Read",
            description="Read employee data",
            privilege_type=PrivilegeType.HR,
            resource_type="hr_system",
            risk_level=RiskLevel.MEDIUM
        )
    ]
    
    # Store permissions
    for perm in sample_permissions:
        intelligence.permissions[perm.permission_id] = perm
    
    # Create sample users
    sample_users = [
        UserAccess(
            user_id="user_001",
            username="john.doe",
            email="john.doe@isectech.com",
            department="Finance",
            job_title="Financial Analyst",
            manager="manager_001",
            effective_permissions=["perm_001", "perm_002"],  # SoD violation
            risk_score=85.0
        ),
        UserAccess(
            user_id="user_002",
            username="jane.smith",
            email="jane.smith@isectech.com",
            department="Finance",
            job_title="Financial Analyst",
            manager="manager_001",
            effective_permissions=["perm_001"],
            risk_score=45.0
        )
    ]
    
    for user in sample_users:
        intelligence.users[user.user_id] = user
    
    # Create sample access history
    access_history = {
        "user_001": [
            {
                "timestamp": (datetime.now(timezone.utc) - timedelta(days=1)).isoformat(),
                "permission_id": "perm_001",
                "action": "create_transaction"
            }
        ],
        "user_002": []  # No recent access
    }
    
    # Run analysis
    results = await intelligence.analyze_privileges(access_history)
    
    print("Privilege Analysis Results:")
    print(f"- Excessive Privileges: {len(results['excessive_privileges'])}")
    print(f"- SoD Violations: {len(results['sod_violations'])}")  
    print(f"- Role Recommendations: {len(results['role_recommendations'])}")
    print(f"- Certification Recommendations: {len(results['certification_recommendations'])}")
    
    # Get user summary
    user_summary = await intelligence.get_user_access_summary("user_001")
    if user_summary:
        print(f"\nUser Summary for {user_summary['username']}:")
        print(f"- Risk Score: {user_summary['risk_score']}")
        print(f"- Total Permissions: {user_summary['total_permissions']}")
        print(f"- High Risk Permissions: {user_summary['high_risk_permissions']}")
    
    # Get system statistics
    stats = await intelligence.get_system_statistics()
    print(f"\nSystem Statistics:")
    print(f"- Total Users: {stats['total_users']}")
    print(f"- High Risk Users: {stats['high_risk_users']}")
    print(f"- Violations Detected: {stats['violations_detected']}")
    
    await intelligence.shutdown()


if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Run example
    asyncio.run(example_usage())