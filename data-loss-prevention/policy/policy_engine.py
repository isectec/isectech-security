#!/usr/bin/env python3
"""
ISECTECH Data Loss Prevention - Policy Engine and Rule Management
Advanced policy engine for flexible and contextual DLP rule management.

This module provides comprehensive policy management capabilities including:
- Declarative policy language (YAML/JSON based)
- Contextual policy enforcement (user, data, environmental context)
- Multi-tenant policy isolation and inheritance
- Policy simulation and testing sandbox
- Real-time policy evaluation with performance optimization
- Integration with identity and business systems

Author: ISECTECH Security Team
Version: 1.0.0
"""

import asyncio
import json
import logging
import sqlite3
import time
import yaml
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any, Union
import hashlib
import re

import redis
from croniter import croniter
import jmespath
from jsonschema import validate, ValidationError

# ISECTECH Security Configuration
from ..config.security_config import SecurityConfig
from ..core.logging import SecurityLogger
from ..core.metrics import MetricsCollector
from ..core.cache import CacheManager


class PolicyAction(Enum):
    """Policy enforcement actions."""
    ALLOW = "allow"
    BLOCK = "block" 
    WARN = "warn"
    QUARANTINE = "quarantine"
    ENCRYPT = "encrypt"
    REDACT = "redact"
    LOG_ONLY = "log_only"
    REQUIRE_APPROVAL = "require_approval"


class PolicyConditionType(Enum):
    """Policy condition types."""
    USER_ATTRIBUTE = "user_attribute"
    DATA_CLASSIFICATION = "data_classification"
    TIME_BASED = "time_based"
    LOCATION_BASED = "location_based"
    DEVICE_ATTRIBUTE = "device_attribute"
    CONTENT_PATTERN = "content_pattern"
    FILE_ATTRIBUTE = "file_attribute"
    BUSINESS_CONTEXT = "business_context"


class PolicyStatus(Enum):
    """Policy status values."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    TESTING = "testing"
    DEPRECATED = "deprecated"
    DRAFT = "draft"


@dataclass
class PolicyCondition:
    """Individual policy condition."""
    id: str
    type: PolicyConditionType
    attribute: str
    operator: str  # equals, contains, regex, greater_than, etc.
    value: Any
    negate: bool = False
    metadata: Dict[str, Any] = None


@dataclass
class PolicyRule:
    """Individual policy rule with conditions and actions."""
    id: str
    name: str
    description: str
    conditions: List[PolicyCondition]
    action: PolicyAction
    priority: int
    enabled: bool = True
    parameters: Dict[str, Any] = None
    exceptions: List[str] = None  # Exception conditions
    metadata: Dict[str, Any] = None


@dataclass
class PolicySet:
    """Collection of related policy rules."""
    id: str
    name: str
    description: str
    tenant_id: str
    rules: List[PolicyRule]
    status: PolicyStatus
    version: str
    effective_date: datetime
    expiry_date: Optional[datetime] = None
    parent_policy_id: Optional[str] = None  # For inheritance
    tags: List[str] = None
    metadata: Dict[str, Any] = None


@dataclass
class PolicyContext:
    """Context information for policy evaluation."""
    user_id: str
    user_attributes: Dict[str, Any]
    data_attributes: Dict[str, Any]
    environment_attributes: Dict[str, Any]
    business_context: Dict[str, Any]
    timestamp: datetime
    tenant_id: str
    session_id: Optional[str] = None


@dataclass
class PolicyDecision:
    """Policy evaluation decision result."""
    decision_id: str
    action: PolicyAction
    policy_set_id: str
    matched_rules: List[str]
    confidence_score: float
    explanation: str
    parameters: Dict[str, Any]
    evaluation_time: float
    context_hash: str
    requires_approval: bool = False
    approval_workflow: Optional[str] = None
    metadata: Dict[str, Any] = None


@dataclass
class PolicySimulation:
    """Policy simulation result."""
    simulation_id: str
    policy_set_id: str
    test_cases: List[Dict[str, Any]]
    results: List[PolicyDecision]
    summary: Dict[str, Any]
    created_time: datetime


class PolicyEngine:
    """
    ISECTECH Policy Engine and Rule Management System
    
    Advanced policy management with:
    - Flexible policy definition language
    - Multi-dimensional contextual evaluation
    - High-performance rule matching
    - Multi-tenant isolation and inheritance
    - Policy simulation and testing
    - Real-time decision caching
    """
    
    def __init__(self, config: SecurityConfig):
        self.config = config
        self.logger = SecurityLogger("policy_engine")
        self.metrics = MetricsCollector("dlp_policy")
        self.cache = CacheManager("policy_cache")
        
        # Database setup
        self.db_path = config.get("dlp.policy_db_path", "dlp_policy_engine.db")
        self._init_database()
        
        # Redis for distributed caching
        self.redis_client = redis.Redis(
            host=config.get("redis.host", "localhost"),
            port=config.get("redis.port", 6379),
            db=config.get("redis.db", 5),
            decode_responses=True
        )
        
        # Thread pool for policy evaluation
        self.thread_pool = ThreadPoolExecutor(
            max_workers=config.get("dlp.policy.max_workers", 8)
        )
        
        # Policy storage
        self.policy_sets: Dict[str, PolicySet] = {}
        self.compiled_patterns: Dict[str, re.Pattern] = {}
        
        # Performance settings
        self.decision_cache_ttl = config.get("dlp.policy.decision_cache_ttl", 300)  # 5 minutes
        self.policy_reload_interval = config.get("dlp.policy.reload_interval", 3600)  # 1 hour
        
        # Policy schema for validation
        self.policy_schema = self._load_policy_schema()
        
        # Load policies
        self._load_policies()
        
        # Start background tasks
        asyncio.create_task(self._policy_reload_task())
        
        self.logger.info("ISECTECH Policy Engine initialized")


    def _init_database(self):
        """Initialize SQLite database with policy schema."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Policy sets table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS policy_sets (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT NOT NULL,
            tenant_id TEXT NOT NULL,
            status TEXT NOT NULL,
            version TEXT NOT NULL,
            effective_date TIMESTAMP NOT NULL,
            expiry_date TIMESTAMP,
            parent_policy_id TEXT,
            tags TEXT,
            metadata TEXT,
            policy_data TEXT NOT NULL,  -- Full policy JSON
            created_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)
        
        # Policy decisions table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS policy_decisions (
            decision_id TEXT PRIMARY KEY,
            action TEXT NOT NULL,
            policy_set_id TEXT NOT NULL,
            matched_rules TEXT NOT NULL,  -- JSON array
            confidence_score REAL NOT NULL,
            explanation TEXT NOT NULL,
            parameters TEXT,
            evaluation_time REAL NOT NULL,
            context_hash TEXT NOT NULL,
            requires_approval BOOLEAN DEFAULT 0,
            approval_workflow TEXT,
            metadata TEXT,
            created_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (policy_set_id) REFERENCES policy_sets (id)
        )
        """)
        
        # Policy simulations table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS policy_simulations (
            simulation_id TEXT PRIMARY KEY,
            policy_set_id TEXT NOT NULL,
            test_cases TEXT NOT NULL,  -- JSON
            results TEXT NOT NULL,     -- JSON
            summary TEXT NOT NULL,     -- JSON
            created_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (policy_set_id) REFERENCES policy_sets (id)
        )
        """)
        
        # Policy audit log table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS policy_audit_log (
            id TEXT PRIMARY KEY,
            event_type TEXT NOT NULL,  -- create, update, delete, evaluate
            policy_set_id TEXT,
            user_id TEXT,
            tenant_id TEXT,
            event_data TEXT,  -- JSON
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)
        
        # Performance indexes
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_policy_sets_tenant ON policy_sets(tenant_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_policy_sets_status ON policy_sets(status)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_policy_decisions_context ON policy_decisions(context_hash)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_policy_decisions_policy ON policy_decisions(policy_set_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_log_tenant ON policy_audit_log(tenant_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_log_event ON policy_audit_log(event_type)")
        
        conn.commit()
        conn.close()
        
        self.logger.info("Policy engine database initialized")


    def _load_policy_schema(self) -> Dict[str, Any]:
        """Load JSON schema for policy validation."""
        return {
            "type": "object",
            "properties": {
                "id": {"type": "string"},
                "name": {"type": "string"},
                "description": {"type": "string"},
                "tenant_id": {"type": "string"},
                "rules": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "id": {"type": "string"},
                            "name": {"type": "string"},
                            "description": {"type": "string"},
                            "conditions": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "properties": {
                                        "type": {"type": "string"},
                                        "attribute": {"type": "string"},
                                        "operator": {"type": "string"},
                                        "value": {},
                                        "negate": {"type": "boolean"}
                                    },
                                    "required": ["type", "attribute", "operator", "value"]
                                }
                            },
                            "action": {"type": "string"},
                            "priority": {"type": "integer"},
                            "enabled": {"type": "boolean"}
                        },
                        "required": ["id", "name", "conditions", "action", "priority"]
                    }
                },
                "status": {"type": "string"},
                "version": {"type": "string"}
            },
            "required": ["id", "name", "tenant_id", "rules", "status", "version"]
        }


    def _load_policies(self):
        """Load policies from database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
        SELECT * FROM policy_sets 
        WHERE status IN ('active', 'testing')
        AND (expiry_date IS NULL OR expiry_date > datetime('now'))
        """)
        
        rows = cursor.fetchall()
        
        for row in rows:
            try:
                policy_data = json.loads(row[9])  # policy_data column
                policy_set = PolicySet(**policy_data)
                self.policy_sets[policy_set.id] = policy_set
                
                # Compile regex patterns for performance
                self._compile_policy_patterns(policy_set)
                
            except Exception as e:
                self.logger.error(f"Failed to load policy {row[0]}: {str(e)}")
        
        conn.close()
        
        # Create default policies if none exist
        if not self.policy_sets:
            self._create_default_policies()
        
        self.logger.info(f"Loaded {len(self.policy_sets)} policy sets")


    def _create_default_policies(self):
        """Create default ISECTECH policy sets."""
        # Default data protection policy
        data_protection_policy = PolicySet(
            id="isec_data_protection_v1",
            name="ISECTECH Data Protection Policy",
            description="Core data protection rules for sensitive information",
            tenant_id="default",
            status=PolicyStatus.ACTIVE,
            version="1.0",
            effective_date=datetime.now(),
            rules=[
                PolicyRule(
                    id="block_pii_external",
                    name="Block PII to External Destinations",
                    description="Block personally identifiable information from being sent externally",
                    conditions=[
                        PolicyCondition(
                            id="pii_classification",
                            type=PolicyConditionType.DATA_CLASSIFICATION,
                            attribute="classification",
                            operator="equals",
                            value="PII"
                        ),
                        PolicyCondition(
                            id="external_destination",
                            type=PolicyConditionType.BUSINESS_CONTEXT,
                            attribute="destination_type",
                            operator="equals",
                            value="external"
                        )
                    ],
                    action=PolicyAction.BLOCK,
                    priority=1,
                    parameters={"notification": True, "log_incident": True}
                ),
                PolicyRule(
                    id="warn_confidential_personal_device",
                    name="Warn on Confidential Data to Personal Device",
                    description="Warning when confidential data is accessed from personal devices",
                    conditions=[
                        PolicyCondition(
                            id="confidential_data",
                            type=PolicyConditionType.DATA_CLASSIFICATION,
                            attribute="sensitivity",
                            operator="equals",
                            value="confidential"
                        ),
                        PolicyCondition(
                            id="personal_device",
                            type=PolicyConditionType.DEVICE_ATTRIBUTE,
                            attribute="device_type",
                            operator="equals",
                            value="personal"
                        )
                    ],
                    action=PolicyAction.WARN,
                    priority=2,
                    parameters={"warning_message": "Accessing confidential data from personal device"}
                )
            ],
            tags=["data_protection", "default", "pii"]
        )
        
        self.add_policy_set(data_protection_policy)
        
        # Time-based access policy
        time_based_policy = PolicySet(
            id="isec_time_based_access_v1",
            name="ISECTECH Time-Based Access Policy",
            description="Time-based restrictions for sensitive data access",
            tenant_id="default",
            status=PolicyStatus.ACTIVE,
            version="1.0",
            effective_date=datetime.now(),
            rules=[
                PolicyRule(
                    id="block_restricted_after_hours",
                    name="Block Restricted Data After Hours",
                    description="Block access to restricted data outside business hours",
                    conditions=[
                        PolicyCondition(
                            id="restricted_data",
                            type=PolicyConditionType.DATA_CLASSIFICATION,
                            attribute="sensitivity",
                            operator="equals",
                            value="restricted"
                        ),
                        PolicyCondition(
                            id="after_hours",
                            type=PolicyConditionType.TIME_BASED,
                            attribute="business_hours",
                            operator="equals",
                            value=False
                        )
                    ],
                    action=PolicyAction.REQUIRE_APPROVAL,
                    priority=1,
                    parameters={"approval_workflow": "manager_approval"}
                )
            ],
            tags=["time_based", "restricted_access"]
        )
        
        self.add_policy_set(time_based_policy)


    def _compile_policy_patterns(self, policy_set: PolicySet):
        """Compile regex patterns in policy conditions for performance."""
        for rule in policy_set.rules:
            for condition in rule.conditions:
                if condition.type == PolicyConditionType.CONTENT_PATTERN and condition.operator == "regex":
                    pattern_key = f"{policy_set.id}_{rule.id}_{condition.id}"
                    try:
                        self.compiled_patterns[pattern_key] = re.compile(
                            str(condition.value), 
                            re.IGNORECASE | re.MULTILINE
                        )
                    except re.error as e:
                        self.logger.error(f"Failed to compile pattern {pattern_key}: {str(e)}")


    async def evaluate_policy_async(self, context: PolicyContext, 
                                  tenant_id: Optional[str] = None) -> PolicyDecision:
        """
        Asynchronously evaluate policies against given context.
        
        Args:
            context: Policy evaluation context
            tenant_id: Optional tenant ID override
            
        Returns:
            Policy decision with action and explanation
        """
        start_time = time.time()
        
        # Use tenant from context or parameter
        eval_tenant_id = tenant_id or context.tenant_id
        
        # Generate context hash for caching
        context_hash = self._generate_context_hash(context)
        
        # Check decision cache
        cache_key = f"policy_decision:{eval_tenant_id}:{context_hash}"
        cached_decision = self.redis_client.get(cache_key)
        
        if cached_decision:
            self.metrics.increment("policy_decision_cache_hits")
            decision_data = json.loads(cached_decision)
            return PolicyDecision(**decision_data)
        
        # Find applicable policy sets
        applicable_policies = self._get_applicable_policies(eval_tenant_id)
        
        if not applicable_policies:
            # Default allow if no policies match
            decision = PolicyDecision(
                decision_id=f"decision_{int(time.time())}_{hashlib.md5(context_hash.encode()).hexdigest()[:8]}",
                action=PolicyAction.ALLOW,
                policy_set_id="default",
                matched_rules=[],
                confidence_score=1.0,
                explanation="No applicable policies found - default allow",
                parameters={},
                evaluation_time=time.time() - start_time,
                context_hash=context_hash
            )
        else:
            # Evaluate policies
            decision = await asyncio.get_event_loop().run_in_executor(
                self.thread_pool,
                self._evaluate_policies_sync,
                applicable_policies, context, context_hash, start_time
            )
        
        # Cache decision
        self.redis_client.setex(
            cache_key,
            self.decision_cache_ttl,
            json.dumps(asdict(decision), default=str)
        )
        
        # Save decision to database
        await self._save_policy_decision(decision)
        
        # Update metrics
        self.metrics.increment("policy_evaluations_completed")
        self.metrics.histogram("policy_evaluation_duration", decision.evaluation_time)
        self.metrics.increment(f"policy_action_{decision.action.value}")
        
        return decision


    def _get_applicable_policies(self, tenant_id: str) -> List[PolicySet]:
        """Get policy sets applicable to the tenant."""
        applicable = []
        
        for policy_set in self.policy_sets.values():
            if policy_set.status == PolicyStatus.ACTIVE and policy_set.tenant_id == tenant_id:
                # Check effective date
                if policy_set.effective_date <= datetime.now():
                    # Check expiry date
                    if not policy_set.expiry_date or policy_set.expiry_date > datetime.now():
                        applicable.append(policy_set)
        
        # Sort by priority (would need to add priority to PolicySet)
        return applicable


    def _evaluate_policies_sync(self, policy_sets: List[PolicySet], context: PolicyContext,
                              context_hash: str, start_time: float) -> PolicyDecision:
        """Synchronously evaluate policies (runs in thread pool)."""
        matched_rules = []
        highest_priority_action = None
        highest_priority = float('inf')
        explanation_parts = []
        decision_parameters = {}
        confidence_scores = []
        
        # Evaluate each policy set
        for policy_set in policy_sets:
            for rule in policy_set.rules:
                if not rule.enabled:
                    continue
                
                # Evaluate rule conditions
                rule_matches, rule_confidence = self._evaluate_rule_conditions(rule, context)
                
                if rule_matches:
                    matched_rules.append(f"{policy_set.id}:{rule.id}")
                    confidence_scores.append(rule_confidence)
                    
                    # Check if this rule has higher priority
                    if rule.priority < highest_priority:
                        highest_priority = rule.priority
                        highest_priority_action = rule.action
                        decision_parameters.update(rule.parameters or {})
                    
                    explanation_parts.append(
                        f"Rule '{rule.name}' matched (priority {rule.priority}): {rule.description}"
                    )
        
        # Determine final decision
        if not matched_rules:
            final_action = PolicyAction.ALLOW
            explanation = "No policy rules matched - default allow"
            confidence_score = 1.0
        else:
            final_action = highest_priority_action
            explanation = "; ".join(explanation_parts)
            confidence_score = sum(confidence_scores) / len(confidence_scores)
        
        # Check if approval is required
        requires_approval = final_action == PolicyAction.REQUIRE_APPROVAL
        approval_workflow = decision_parameters.get("approval_workflow") if requires_approval else None
        
        decision_id = f"decision_{int(time.time())}_{hashlib.md5(context_hash.encode()).hexdigest()[:8]}"
        
        return PolicyDecision(
            decision_id=decision_id,
            action=final_action,
            policy_set_id=policy_sets[0].id if policy_sets else "default",
            matched_rules=matched_rules,
            confidence_score=confidence_score,
            explanation=explanation,
            parameters=decision_parameters,
            evaluation_time=time.time() - start_time,
            context_hash=context_hash,
            requires_approval=requires_approval,
            approval_workflow=approval_workflow,
            metadata={"evaluated_policies": len(policy_sets), "total_rules": sum(len(ps.rules) for ps in policy_sets)}
        )


    def _evaluate_rule_conditions(self, rule: PolicyRule, context: PolicyContext) -> Tuple[bool, float]:
        """Evaluate all conditions in a rule."""
        condition_results = []
        confidence_scores = []
        
        for condition in rule.conditions:
            result, confidence = self._evaluate_single_condition(condition, context)
            
            # Apply negation if specified
            if condition.negate:
                result = not result
            
            condition_results.append(result)
            confidence_scores.append(confidence)
        
        # All conditions must be true for rule to match (AND logic)
        rule_matches = all(condition_results)
        
        # Calculate overall confidence
        overall_confidence = min(confidence_scores) if confidence_scores else 0.0
        
        return rule_matches, overall_confidence


    def _evaluate_single_condition(self, condition: PolicyCondition, context: PolicyContext) -> Tuple[bool, float]:
        """Evaluate a single policy condition."""
        try:
            if condition.type == PolicyConditionType.USER_ATTRIBUTE:
                return self._evaluate_user_attribute(condition, context)
            
            elif condition.type == PolicyConditionType.DATA_CLASSIFICATION:
                return self._evaluate_data_classification(condition, context)
            
            elif condition.type == PolicyConditionType.TIME_BASED:
                return self._evaluate_time_based(condition, context)
            
            elif condition.type == PolicyConditionType.LOCATION_BASED:
                return self._evaluate_location_based(condition, context)
            
            elif condition.type == PolicyConditionType.DEVICE_ATTRIBUTE:
                return self._evaluate_device_attribute(condition, context)
            
            elif condition.type == PolicyConditionType.CONTENT_PATTERN:
                return self._evaluate_content_pattern(condition, context)
                
            elif condition.type == PolicyConditionType.FILE_ATTRIBUTE:
                return self._evaluate_file_attribute(condition, context)
                
            elif condition.type == PolicyConditionType.BUSINESS_CONTEXT:
                return self._evaluate_business_context(condition, context)
            
            else:
                self.logger.warning(f"Unknown condition type: {condition.type}")
                return False, 0.0
        
        except Exception as e:
            self.logger.error(f"Error evaluating condition {condition.id}: {str(e)}")
            return False, 0.0


    def _evaluate_user_attribute(self, condition: PolicyCondition, context: PolicyContext) -> Tuple[bool, float]:
        """Evaluate user attribute condition."""
        user_value = context.user_attributes.get(condition.attribute)
        
        if user_value is None:
            return False, 0.0
        
        return self._compare_values(user_value, condition.operator, condition.value), 1.0


    def _evaluate_data_classification(self, condition: PolicyCondition, context: PolicyContext) -> Tuple[bool, float]:
        """Evaluate data classification condition."""
        data_value = context.data_attributes.get(condition.attribute)
        
        if data_value is None:
            return False, 0.0
        
        return self._compare_values(data_value, condition.operator, condition.value), 1.0


    def _evaluate_time_based(self, condition: PolicyCondition, context: PolicyContext) -> Tuple[bool, float]:
        """Evaluate time-based condition."""
        if condition.attribute == "business_hours":
            # Check if current time is within business hours
            current_hour = context.timestamp.hour
            current_weekday = context.timestamp.weekday()  # Monday = 0
            
            # Business hours: Monday-Friday, 9 AM - 5 PM
            is_business_hours = (0 <= current_weekday <= 4) and (9 <= current_hour <= 17)
            
            return self._compare_values(is_business_hours, condition.operator, condition.value), 1.0
        
        elif condition.attribute == "time_of_day":
            current_hour = context.timestamp.hour
            return self._compare_values(current_hour, condition.operator, condition.value), 1.0
        
        elif condition.attribute == "day_of_week":
            current_weekday = context.timestamp.weekday()
            return self._compare_values(current_weekday, condition.operator, condition.value), 1.0
        
        return False, 0.0


    def _evaluate_location_based(self, condition: PolicyCondition, context: PolicyContext) -> Tuple[bool, float]:
        """Evaluate location-based condition."""
        location_value = context.environment_attributes.get(condition.attribute)
        
        if location_value is None:
            return False, 0.0
        
        return self._compare_values(location_value, condition.operator, condition.value), 1.0


    def _evaluate_device_attribute(self, condition: PolicyCondition, context: PolicyContext) -> Tuple[bool, float]:
        """Evaluate device attribute condition."""
        device_value = context.environment_attributes.get(condition.attribute)
        
        if device_value is None:
            return False, 0.0
        
        return self._compare_values(device_value, condition.operator, condition.value), 1.0


    def _evaluate_content_pattern(self, condition: PolicyCondition, context: PolicyContext) -> Tuple[bool, float]:
        """Evaluate content pattern condition."""
        content = context.data_attributes.get("content", "")
        
        if condition.operator == "regex":
            pattern_key = f"pattern_{condition.id}"
            if pattern_key in self.compiled_patterns:
                matches = self.compiled_patterns[pattern_key].findall(content)
                return len(matches) > 0, 1.0 if matches else 0.0
            else:
                # Fallback to runtime compilation
                try:
                    pattern = re.compile(str(condition.value), re.IGNORECASE | re.MULTILINE)
                    matches = pattern.findall(content)
                    return len(matches) > 0, 1.0 if matches else 0.0
                except re.error:
                    return False, 0.0
        
        elif condition.operator == "contains":
            result = str(condition.value) in content
            return result, 1.0 if result else 0.0
        
        return False, 0.0


    def _evaluate_file_attribute(self, condition: PolicyCondition, context: PolicyContext) -> Tuple[bool, float]:
        """Evaluate file attribute condition."""
        file_value = context.data_attributes.get(condition.attribute)
        
        if file_value is None:
            return False, 0.0
        
        return self._compare_values(file_value, condition.operator, condition.value), 1.0


    def _evaluate_business_context(self, condition: PolicyCondition, context: PolicyContext) -> Tuple[bool, float]:
        """Evaluate business context condition."""
        business_value = context.business_context.get(condition.attribute)
        
        if business_value is None:
            return False, 0.0
        
        return self._compare_values(business_value, condition.operator, condition.value), 1.0


    def _compare_values(self, actual: Any, operator: str, expected: Any) -> bool:
        """Compare two values using the specified operator."""
        try:
            if operator == "equals":
                return actual == expected
            elif operator == "not_equals":
                return actual != expected
            elif operator == "contains":
                return str(expected) in str(actual)
            elif operator == "not_contains":
                return str(expected) not in str(actual)
            elif operator == "starts_with":
                return str(actual).startswith(str(expected))
            elif operator == "ends_with":
                return str(actual).endswith(str(expected))
            elif operator == "greater_than":
                return float(actual) > float(expected)
            elif operator == "less_than":
                return float(actual) < float(expected)
            elif operator == "greater_equal":
                return float(actual) >= float(expected)
            elif operator == "less_equal":
                return float(actual) <= float(expected)
            elif operator == "in_list":
                return actual in expected if isinstance(expected, list) else False
            elif operator == "not_in_list":
                return actual not in expected if isinstance(expected, list) else True
            elif operator == "regex":
                pattern = re.compile(str(expected), re.IGNORECASE)
                return bool(pattern.search(str(actual)))
            else:
                self.logger.warning(f"Unknown operator: {operator}")
                return False
        
        except (ValueError, TypeError) as e:
            self.logger.debug(f"Value comparison error: {str(e)}")
            return False


    def _generate_context_hash(self, context: PolicyContext) -> str:
        """Generate hash for context to use as cache key."""
        # Create deterministic hash of context
        context_data = {
            "user_id": context.user_id,
            "user_attributes": sorted(context.user_attributes.items()) if context.user_attributes else [],
            "data_attributes": sorted(context.data_attributes.items()) if context.data_attributes else [],
            "environment_attributes": sorted(context.environment_attributes.items()) if context.environment_attributes else [],
            "business_context": sorted(context.business_context.items()) if context.business_context else [],
            "tenant_id": context.tenant_id
        }
        
        context_json = json.dumps(context_data, sort_keys=True)
        return hashlib.sha256(context_json.encode()).hexdigest()


    async def simulate_policy_async(self, policy_set_id: str, 
                                  test_cases: List[PolicyContext]) -> PolicySimulation:
        """
        Simulate policy execution against test cases.
        
        Args:
            policy_set_id: ID of policy set to simulate
            test_cases: List of test contexts to evaluate
            
        Returns:
            Policy simulation results
        """
        if policy_set_id not in self.policy_sets:
            raise ValueError(f"Policy set not found: {policy_set_id}")
        
        simulation_id = f"sim_{policy_set_id}_{int(time.time())}"
        results = []
        
        # Evaluate each test case
        for i, test_context in enumerate(test_cases):
            try:
                decision = await self.evaluate_policy_async(test_context)
                results.append(decision)
            except Exception as e:
                self.logger.error(f"Simulation error for test case {i}: {str(e)}")
                # Create error decision
                error_decision = PolicyDecision(
                    decision_id=f"sim_error_{i}",
                    action=PolicyAction.ALLOW,
                    policy_set_id=policy_set_id,
                    matched_rules=[],
                    confidence_score=0.0,
                    explanation=f"Simulation error: {str(e)}",
                    parameters={},
                    evaluation_time=0.0,
                    context_hash="error"
                )
                results.append(error_decision)
        
        # Generate summary
        action_counts = {}
        total_eval_time = 0.0
        confidence_scores = []
        
        for result in results:
            action_counts[result.action.value] = action_counts.get(result.action.value, 0) + 1
            total_eval_time += result.evaluation_time
            confidence_scores.append(result.confidence_score)
        
        summary = {
            "total_test_cases": len(test_cases),
            "action_distribution": action_counts,
            "average_evaluation_time": total_eval_time / len(results) if results else 0.0,
            "average_confidence": sum(confidence_scores) / len(confidence_scores) if confidence_scores else 0.0,
            "simulation_duration": total_eval_time
        }
        
        simulation = PolicySimulation(
            simulation_id=simulation_id,
            policy_set_id=policy_set_id,
            test_cases=[asdict(tc) for tc in test_cases],
            results=results,
            summary=summary,
            created_time=datetime.now()
        )
        
        # Save simulation to database
        await self._save_policy_simulation(simulation)
        
        self.logger.info(f"Policy simulation {simulation_id} completed with {len(results)} results")
        return simulation


    def add_policy_set(self, policy_set: PolicySet):
        """Add or update a policy set."""
        # Validate policy set
        try:
            policy_data = asdict(policy_set)
            validate(policy_data, self.policy_schema)
        except ValidationError as e:
            raise ValueError(f"Policy validation failed: {str(e)}")
        
        # Save to database
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
        INSERT OR REPLACE INTO policy_sets 
        (id, name, description, tenant_id, status, version, effective_date,
         expiry_date, parent_policy_id, tags, metadata, policy_data)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            policy_set.id,
            policy_set.name,
            policy_set.description,
            policy_set.tenant_id,
            policy_set.status.value,
            policy_set.version,
            policy_set.effective_date.isoformat(),
            policy_set.expiry_date.isoformat() if policy_set.expiry_date else None,
            policy_set.parent_policy_id,
            json.dumps(policy_set.tags or []),
            json.dumps(policy_set.metadata or {}),
            json.dumps(asdict(policy_set), default=str)
        ))
        
        conn.commit()
        conn.close()
        
        # Update in-memory storage
        self.policy_sets[policy_set.id] = policy_set
        
        # Compile patterns for performance
        self._compile_policy_patterns(policy_set)
        
        # Clear related cache
        self._clear_policy_cache(policy_set.tenant_id)
        
        # Log audit event
        self._log_audit_event("create", policy_set.id, None, policy_set.tenant_id, asdict(policy_set))
        
        self.logger.info(f"Added policy set: {policy_set.name}")


    async def _save_policy_decision(self, decision: PolicyDecision):
        """Save policy decision to database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
        INSERT INTO policy_decisions 
        (decision_id, action, policy_set_id, matched_rules, confidence_score,
         explanation, parameters, evaluation_time, context_hash, requires_approval,
         approval_workflow, metadata)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            decision.decision_id,
            decision.action.value,
            decision.policy_set_id,
            json.dumps(decision.matched_rules),
            decision.confidence_score,
            decision.explanation,
            json.dumps(decision.parameters),
            decision.evaluation_time,
            decision.context_hash,
            decision.requires_approval,
            decision.approval_workflow,
            json.dumps(decision.metadata or {})
        ))
        
        conn.commit()
        conn.close()


    async def _save_policy_simulation(self, simulation: PolicySimulation):
        """Save policy simulation to database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
        INSERT INTO policy_simulations 
        (simulation_id, policy_set_id, test_cases, results, summary)
        VALUES (?, ?, ?, ?, ?)
        """, (
            simulation.simulation_id,
            simulation.policy_set_id,
            json.dumps(simulation.test_cases, default=str),
            json.dumps([asdict(r) for r in simulation.results], default=str),
            json.dumps(simulation.summary)
        ))
        
        conn.commit()
        conn.close()


    def _clear_policy_cache(self, tenant_id: str):
        """Clear policy decision cache for tenant."""
        pattern = f"policy_decision:{tenant_id}:*"
        keys = self.redis_client.keys(pattern)
        if keys:
            self.redis_client.delete(*keys)


    def _log_audit_event(self, event_type: str, policy_set_id: Optional[str], 
                        user_id: Optional[str], tenant_id: str, event_data: Dict[str, Any]):
        """Log audit event to database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        event_id = f"audit_{int(time.time())}_{hashlib.md5(f'{event_type}{policy_set_id}'.encode()).hexdigest()[:8]}"
        
        cursor.execute("""
        INSERT INTO policy_audit_log 
        (id, event_type, policy_set_id, user_id, tenant_id, event_data)
        VALUES (?, ?, ?, ?, ?, ?)
        """, (
            event_id, event_type, policy_set_id, user_id, tenant_id,
            json.dumps(event_data, default=str)
        ))
        
        conn.commit()
        conn.close()


    async def _policy_reload_task(self):
        """Background task to reload policies periodically."""
        while True:
            try:
                await asyncio.sleep(self.policy_reload_interval)
                self._load_policies()
                self.logger.debug("Policy reload completed")
            except Exception as e:
                self.logger.error(f"Policy reload failed: {str(e)}")


    def get_policy_statistics(self) -> Dict[str, Any]:
        """Get policy engine statistics."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Total policy sets
        cursor.execute("SELECT COUNT(*) FROM policy_sets WHERE status = 'active'")
        active_policies = cursor.fetchone()[0]
        
        # Total decisions today
        cursor.execute("""
        SELECT COUNT(*) FROM policy_decisions 
        WHERE date(created_time) = date('now')
        """)
        decisions_today = cursor.fetchone()[0]
        
        # Decision actions distribution
        cursor.execute("""
        SELECT action, COUNT(*) 
        FROM policy_decisions 
        WHERE created_time >= datetime('now', '-7 days')
        GROUP BY action
        """)
        action_distribution = dict(cursor.fetchall())
        
        # Average evaluation time
        cursor.execute("""
        SELECT AVG(evaluation_time) 
        FROM policy_decisions 
        WHERE created_time >= datetime('now', '-1 day')
        """)
        avg_eval_time = cursor.fetchone()[0] or 0.0
        
        conn.close()
        
        return {
            "active_policy_sets": active_policies,
            "decisions_today": decisions_today,
            "action_distribution_7d": action_distribution,
            "average_evaluation_time": round(avg_eval_time, 4),
            "loaded_policies": len(self.policy_sets),
            "compiled_patterns": len(self.compiled_patterns)
        }


    def __del__(self):
        """Cleanup resources."""
        if hasattr(self, 'thread_pool'):
            self.thread_pool.shutdown(wait=True)
        if hasattr(self, 'redis_client'):
            self.redis_client.close()