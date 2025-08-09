"""
Production-grade authorization for iSECTECH AI services.

This module provides comprehensive authorization capabilities including:
- Role-Based Access Control (RBAC)
- Attribute-Based Access Control (ABAC)
- Security context management
- Multi-tenant authorization
- Fine-grained permission control
"""

from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Set, Union

from ..config.settings import SecurityClassification
from .authentication import UserClaims


class AuthorizationError(Exception):
    """Base exception for authorization operations."""
    pass


class AccessDeniedError(AuthorizationError):
    """Exception for access denied scenarios."""
    pass


class ResourceType(str, Enum):
    """Types of resources that can be protected."""
    MODEL = "model"
    DATA = "data"
    API_ENDPOINT = "api_endpoint"
    ANALYSIS_RESULT = "analysis_result"
    THREAT_INTELLIGENCE = "threat_intelligence"
    SECURITY_EVENT = "security_event"
    COMPLIANCE_REPORT = "compliance_report"
    USER_BEHAVIOR = "user_behavior"
    ANOMALY_DETECTION = "anomaly_detection"


class Action(str, Enum):
    """Actions that can be performed on resources."""
    CREATE = "create"
    READ = "read"
    UPDATE = "update"
    DELETE = "delete"
    EXECUTE = "execute"
    ANALYZE = "analyze"
    EXPORT = "export"
    SHARE = "share"
    APPROVE = "approve"
    INVESTIGATE = "investigate"


class Resource:
    """Represents a protected resource with attributes."""
    
    def __init__(self, resource_id: str, resource_type: ResourceType,
                 tenant_id: str, security_classification: SecurityClassification,
                 owner_id: Optional[str] = None, attributes: Optional[Dict] = None):
        self.resource_id = resource_id
        self.resource_type = resource_type
        self.tenant_id = tenant_id
        self.security_classification = security_classification
        self.owner_id = owner_id
        self.attributes = attributes or {}
        self.created_at = datetime.utcnow()
        self.updated_at = datetime.utcnow()
    
    def has_attribute(self, key: str, value: str = None) -> bool:
        """Check if resource has specific attribute."""
        if key not in self.attributes:
            return False
        
        if value is None:
            return True
        
        return self.attributes[key] == value
    
    def get_attribute(self, key: str, default=None):
        """Get resource attribute value."""
        return self.attributes.get(key, default)


class SecurityContext:
    """Security context for authorization decisions."""
    
    def __init__(self, user_claims: UserClaims, request_ip: str = None,
                 request_time: datetime = None, additional_context: Dict = None):
        self.user_claims = user_claims
        self.request_ip = request_ip
        self.request_time = request_time or datetime.utcnow()
        self.additional_context = additional_context or {}
    
    @property
    def user_id(self) -> str:
        """Get user ID from claims."""
        return self.user_claims.user_id
    
    @property
    def tenant_id(self) -> str:
        """Get tenant ID from claims."""
        return self.user_claims.tenant_id
    
    @property
    def roles(self) -> List[str]:
        """Get user roles from claims."""
        return self.user_claims.roles
    
    @property
    def security_clearance(self) -> SecurityClassification:
        """Get user security clearance from claims."""
        return self.user_claims.security_clearance
    
    def has_role(self, role: str) -> bool:
        """Check if user has specific role."""
        return self.user_claims.has_role(role)
    
    def has_permission(self, permission: str) -> bool:
        """Check if user has specific permission."""
        return self.user_claims.has_permission(permission)


class PolicyRule:
    """Represents an authorization policy rule."""
    
    def __init__(self, rule_id: str, resource_type: ResourceType,
                 action: Action, conditions: Dict,
                 effect: str = "allow", priority: int = 0):
        self.rule_id = rule_id
        self.resource_type = resource_type
        self.action = action
        self.conditions = conditions
        self.effect = effect  # "allow" or "deny"
        self.priority = priority
    
    def evaluate(self, context: SecurityContext, resource: Resource) -> bool:
        """Evaluate if this rule applies to the given context and resource."""
        # Check resource type
        if resource.resource_type != self.resource_type:
            return False
        
        # Evaluate all conditions
        for condition_type, condition_value in self.conditions.items():
            if not self._evaluate_condition(condition_type, condition_value, context, resource):
                return False
        
        return True
    
    def _evaluate_condition(self, condition_type: str, condition_value,
                           context: SecurityContext, resource: Resource) -> bool:
        """Evaluate a specific condition."""
        if condition_type == "roles":
            required_roles = condition_value if isinstance(condition_value, list) else [condition_value]
            return any(context.has_role(role) for role in required_roles)
        
        elif condition_type == "permissions":
            required_permissions = condition_value if isinstance(condition_value, list) else [condition_value]
            return any(context.has_permission(perm) for perm in required_permissions)
        
        elif condition_type == "security_clearance":
            required_clearance = SecurityClassification(condition_value)
            return context.user_claims.can_access_classification(required_clearance)
        
        elif condition_type == "tenant_id":
            return context.tenant_id == condition_value
        
        elif condition_type == "owner":
            return context.user_id == resource.owner_id
        
        elif condition_type == "resource_classification":
            resource_clearance = resource.security_classification
            return context.user_claims.can_access_classification(resource_clearance)
        
        elif condition_type == "time_restriction":
            # Time-based access control (e.g., business hours only)
            start_hour, end_hour = condition_value
            current_hour = context.request_time.hour
            return start_hour <= current_hour <= end_hour
        
        elif condition_type == "ip_restriction":
            # IP-based access control
            allowed_ips = condition_value if isinstance(condition_value, list) else [condition_value]
            return context.request_ip in allowed_ips
        
        elif condition_type == "resource_attribute":
            # Resource attribute-based conditions
            attr_name, attr_value = condition_value
            return resource.has_attribute(attr_name, attr_value)
        
        else:
            # Unknown condition type - default to False for security
            return False


class RoleBasedAccessControl:
    """Role-Based Access Control (RBAC) implementation."""
    
    def __init__(self):
        self.role_permissions: Dict[str, Set[str]] = {
            # Administrative roles
            "admin": {
                "create_model", "read_model", "update_model", "delete_model",
                "read_all_data", "export_data", "manage_users", "manage_tenants",
                "read_threats", "investigate_threats", "approve_actions"
            },
            
            # Security analyst roles
            "security_analyst": {
                "read_model", "execute_model", "read_threats", "investigate_threats",
                "read_events", "analyze_events", "create_reports", "read_compliance"
            },
            
            # SOC operator roles
            "soc_operator": {
                "read_model", "execute_model", "read_threats", "read_events",
                "investigate_threats", "acknowledge_alerts", "escalate_incidents"
            },
            
            # Data scientist roles
            "data_scientist": {
                "create_model", "read_model", "update_model", "execute_model",
                "read_training_data", "analyze_data", "export_results"
            },
            
            # Compliance officer roles
            "compliance_officer": {
                "read_compliance", "create_reports", "export_reports",
                "read_audit_logs", "approve_actions"
            },
            
            # Service account roles
            "service": {
                "read_model", "execute_model", "read_events", "write_events",
                "read_threats", "write_threats"
            },
            
            # Read-only user roles
            "viewer": {
                "read_model", "read_events", "read_threats", "read_reports"
            }
        }
        
        self.role_hierarchy: Dict[str, List[str]] = {
            "admin": ["security_analyst", "soc_operator", "data_scientist", "compliance_officer", "viewer"],
            "security_analyst": ["soc_operator", "viewer"],
            "data_scientist": ["viewer"],
            "compliance_officer": ["viewer"],
            "soc_operator": ["viewer"]
        }
    
    def get_effective_permissions(self, roles: List[str]) -> Set[str]:
        """Get all effective permissions for given roles."""
        permissions = set()
        
        for role in roles:
            # Add direct permissions
            permissions.update(self.role_permissions.get(role, set()))
            
            # Add inherited permissions from role hierarchy
            inherited_roles = self.role_hierarchy.get(role, [])
            for inherited_role in inherited_roles:
                permissions.update(self.role_permissions.get(inherited_role, set()))
        
        return permissions
    
    def has_permission(self, roles: List[str], permission: str) -> bool:
        """Check if roles have specific permission."""
        effective_permissions = self.get_effective_permissions(roles)
        return permission in effective_permissions


class AttributeBasedAccessControl:
    """Attribute-Based Access Control (ABAC) implementation."""
    
    def __init__(self):
        self.policies: List[PolicyRule] = []
        self._load_default_policies()
    
    def _load_default_policies(self):
        """Load default ABAC policies."""
        # Policy: Allow users to read their own tenant's data
        self.policies.append(PolicyRule(
            rule_id="tenant_isolation",
            resource_type=ResourceType.DATA,
            action=Action.READ,
            conditions={"tenant_id": "{{context.tenant_id}}"},
            effect="allow",
            priority=100
        ))
        
        # Policy: Allow access based on security clearance
        self.policies.append(PolicyRule(
            rule_id="security_clearance",
            resource_type=ResourceType.THREAT_INTELLIGENCE,
            action=Action.READ,
            conditions={"resource_classification": "{{resource.security_classification}}"},
            effect="allow",
            priority=90
        ))
        
        # Policy: Allow owners to modify their resources
        self.policies.append(PolicyRule(
            rule_id="owner_access",
            resource_type=ResourceType.MODEL,
            action=Action.UPDATE,
            conditions={"owner": True},
            effect="allow",
            priority=80
        ))
        
        # Policy: Restrict administrative actions to business hours
        self.policies.append(PolicyRule(
            rule_id="business_hours_admin",
            resource_type=ResourceType.MODEL,
            action=Action.DELETE,
            conditions={
                "roles": ["admin"],
                "time_restriction": [9, 17]  # 9 AM to 5 PM
            },
            effect="allow",
            priority=70
        ))
    
    def add_policy(self, policy: PolicyRule):
        """Add new policy rule."""
        self.policies.append(policy)
        # Sort by priority (higher priority first)
        self.policies.sort(key=lambda p: p.priority, reverse=True)
    
    def evaluate_access(self, context: SecurityContext, resource: Resource,
                       action: Action) -> bool:
        """Evaluate access using ABAC policies."""
        applicable_policies = [
            policy for policy in self.policies
            if policy.resource_type == resource.resource_type and policy.action == action
        ]
        
        for policy in applicable_policies:
            if policy.evaluate(context, resource):
                return policy.effect == "allow"
        
        # Default deny if no applicable policies
        return False


class AuthorizationManager:
    """Central authorization management."""
    
    def __init__(self):
        self.rbac = RoleBasedAccessControl()
        self.abac = AttributeBasedAccessControl()
        self.access_log: List[Dict] = []
    
    def authorize(self, context: SecurityContext, resource: Resource,
                  action: Action, use_abac: bool = True) -> bool:
        """Authorize access to resource with given action."""
        try:
            # First check tenant isolation
            if not self._check_tenant_isolation(context, resource):
                self._log_access_decision(context, resource, action, False, "tenant_isolation_failed")
                raise AccessDeniedError("Cross-tenant access denied")
            
            # Check security clearance
            if not context.user_claims.can_access_classification(resource.security_classification):
                self._log_access_decision(context, resource, action, False, "insufficient_clearance")
                raise AccessDeniedError("Insufficient security clearance")
            
            # Use ABAC if enabled and applicable
            if use_abac:
                abac_result = self.abac.evaluate_access(context, resource, action)
                if abac_result:
                    self._log_access_decision(context, resource, action, True, "abac_allow")
                    return True
            
            # Fall back to RBAC
            permission_map = {
                (ResourceType.MODEL, Action.READ): "read_model",
                (ResourceType.MODEL, Action.CREATE): "create_model",
                (ResourceType.MODEL, Action.UPDATE): "update_model",
                (ResourceType.MODEL, Action.DELETE): "delete_model",
                (ResourceType.MODEL, Action.EXECUTE): "execute_model",
                (ResourceType.DATA, Action.READ): "read_data",
                (ResourceType.DATA, Action.EXPORT): "export_data",
                (ResourceType.THREAT_INTELLIGENCE, Action.READ): "read_threats",
                (ResourceType.SECURITY_EVENT, Action.READ): "read_events",
                (ResourceType.SECURITY_EVENT, Action.ANALYZE): "analyze_events",
                (ResourceType.ANOMALY_DETECTION, Action.INVESTIGATE): "investigate_threats",
                (ResourceType.COMPLIANCE_REPORT, Action.READ): "read_compliance",
                (ResourceType.COMPLIANCE_REPORT, Action.CREATE): "create_reports",
            }
            
            required_permission = permission_map.get((resource.resource_type, action))
            if required_permission:
                rbac_result = self.rbac.has_permission(context.roles, required_permission)
                self._log_access_decision(context, resource, action, rbac_result, 
                                        "rbac_allow" if rbac_result else "rbac_deny")
                return rbac_result
            
            # If no specific permission mapping, deny by default
            self._log_access_decision(context, resource, action, False, "no_permission_mapping")
            return False
        
        except Exception as e:
            self._log_access_decision(context, resource, action, False, f"error_{type(e).__name__}")
            return False
    
    def _check_tenant_isolation(self, context: SecurityContext, resource: Resource) -> bool:
        """Check tenant isolation rules."""
        # Service accounts and admins can access cross-tenant resources
        if context.has_role("service") or context.has_role("admin"):
            return True
        
        # Regular users can only access their tenant's resources
        return context.tenant_id == resource.tenant_id
    
    def _log_access_decision(self, context: SecurityContext, resource: Resource,
                           action: Action, granted: bool, reason: str):
        """Log access decision for audit trail."""
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "user_id": context.user_id,
            "tenant_id": context.tenant_id,
            "resource_id": resource.resource_id,
            "resource_type": resource.resource_type.value,
            "action": action.value,
            "granted": granted,
            "reason": reason,
            "request_ip": context.request_ip,
            "security_clearance": context.security_clearance.value,
            "resource_classification": resource.security_classification.value
        }
        
        self.access_log.append(log_entry)
        
        # In production, this would be sent to audit logging system
        if len(self.access_log) > 10000:  # Prevent memory buildup
            self.access_log = self.access_log[-5000:]  # Keep last 5000 entries
    
    def get_access_summary(self, user_id: str = None, 
                          time_window_hours: int = 24) -> Dict:
        """Get access summary for monitoring."""
        cutoff_time = datetime.utcnow() - timedelta(hours=time_window_hours)
        
        relevant_logs = [
            log for log in self.access_log
            if datetime.fromisoformat(log["timestamp"]) >= cutoff_time
            and (user_id is None or log["user_id"] == user_id)
        ]
        
        total_requests = len(relevant_logs)
        granted_requests = sum(1 for log in relevant_logs if log["granted"])
        denied_requests = total_requests - granted_requests
        
        return {
            "total_requests": total_requests,
            "granted_requests": granted_requests,
            "denied_requests": denied_requests,
            "success_rate": granted_requests / total_requests if total_requests > 0 else 0,
            "unique_users": len(set(log["user_id"] for log in relevant_logs)),
            "unique_resources": len(set(log["resource_id"] for log in relevant_logs))
        }
    
    def create_resource(self, resource_id: str, resource_type: ResourceType,
                       tenant_id: str, security_classification: SecurityClassification,
                       owner_id: str = None, attributes: Dict = None) -> Resource:
        """Create a new protected resource."""
        return Resource(
            resource_id=resource_id,
            resource_type=resource_type,
            tenant_id=tenant_id,
            security_classification=security_classification,
            owner_id=owner_id,
            attributes=attributes
        )


# Global authorization manager instance
_authz_manager: Optional[AuthorizationManager] = None


def get_authorization_manager() -> AuthorizationManager:
    """Get global authorization manager instance."""
    global _authz_manager
    if _authz_manager is None:
        _authz_manager = AuthorizationManager()
    return _authz_manager


def authorize_access(context: SecurityContext, resource: Resource, 
                    action: Action) -> bool:
    """Convenience function for authorization checks."""
    authz_manager = get_authorization_manager()
    return authz_manager.authorize(context, resource, action)