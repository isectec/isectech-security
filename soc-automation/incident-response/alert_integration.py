"""
SOC Automation - Alert Integration for Incident Response

Integration layer that connects the alert triage system with incident response
orchestration. Monitors incoming alerts and triggers appropriate incident response
workflows based on alert characteristics and organizational policies.
"""

import asyncio
import logging
import json
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass
from enum import Enum
import redis.asyncio as redis
from elasticsearch import AsyncElasticsearch
from prometheus_client import Counter, Histogram
import structlog

from .orchestration_engine import (
    IncidentResponseOrchestrator, 
    IncidentSeverity, 
    EvidenceCollectionRequest
)
from ..forensics.evidence_collection_engine import (
    DigitalForensicsEvidenceCollector,
    EvidenceType
)

logger = structlog.get_logger(__name__)

# Prometheus metrics
ALERTS_PROCESSED_FOR_IR = Counter('soc_alerts_processed_incident_response_total', 'Alerts processed for incident response', ['outcome'])
INCIDENT_RESPONSE_TRIGGERED = Counter('soc_incident_response_triggered_total', 'Incident responses triggered', ['alert_type', 'severity'])
ALERT_TO_INCIDENT_TIME = Histogram('soc_alert_to_incident_seconds', 'Time from alert to incident creation')

class AlertTriggerPolicy(Enum):
    """Alert trigger policies for incident response"""
    SEVERITY_BASED = "severity_based"
    CATEGORY_BASED = "category_based"
    SOURCE_BASED = "source_based" 
    CORRELATION_BASED = "correlation_based"
    ML_CONFIDENCE_BASED = "ml_confidence_based"
    MANUAL_ESCALATION = "manual_escalation"

@dataclass
class TriggerRule:
    """Rule for triggering incident response"""
    rule_id: str
    name: str
    description: str
    policy_type: AlertTriggerPolicy
    conditions: Dict[str, Any]
    actions: List[str]
    priority: int = 5
    enabled: bool = True
    evidence_collection: bool = False
    immediate_containment: bool = False

@dataclass
class AlertCorrelation:
    """Alert correlation data"""
    correlation_id: str
    primary_alert_id: str
    related_alert_ids: List[str]
    correlation_score: float
    correlation_type: str  # temporal, spatial, pattern, etc.
    created_at: datetime

class AlertIncidentIntegration:
    """
    Integration service between alert triage and incident response
    
    Responsibilities:
    - Monitor alert streams from alert manager
    - Apply trigger rules to determine incident response needs
    - Correlate related alerts for context
    - Trigger incident response orchestration
    - Initiate evidence collection
    - Provide feedback to alert triage system
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        
        # Component configurations
        self.redis_config = config.get('redis', {})
        self.elasticsearch_config = config.get('elasticsearch', {})
        self.orchestrator_config = config.get('orchestrator', {})
        self.evidence_collector_config = config.get('evidence_collector', {})
        
        # Initialize components
        self.redis_client: redis.Redis = None
        self.elasticsearch: AsyncElasticsearch = None
        self.orchestrator: IncidentResponseOrchestrator = None
        self.evidence_collector: DigitalForensicsEvidenceCollector = None
        
        # Runtime state
        self.trigger_rules: Dict[str, TriggerRule] = {}
        self.active_correlations: Dict[str, AlertCorrelation] = {}
        self.processed_alerts: Set[str] = set()
        self.running = False
        
        # Configuration
        self.alert_stream_keys = config.get('alert_stream_keys', ['alerts:all'])
        self.correlation_window_seconds = config.get('correlation_window', 300)  # 5 minutes
        self.max_correlation_alerts = config.get('max_correlation_alerts', 50)
        self.evidence_auto_collect = config.get('evidence_auto_collect', True)
        
        logger.info("AlertIncidentIntegration initialized",
                   alert_streams=len(self.alert_stream_keys),
                   correlation_window=self.correlation_window_seconds)
    
    async def initialize(self):
        """Initialize the integration service"""
        try:
            # Initialize Redis connection
            self.redis_client = redis.Redis(
                host=self.redis_config.get('host', 'localhost'),
                port=self.redis_config.get('port', 6379),
                db=self.redis_config.get('db', 0),
                decode_responses=True
            )
            await self.redis_client.ping()
            
            # Initialize Elasticsearch
            self.elasticsearch = AsyncElasticsearch([{
                'host': self.elasticsearch_config.get('host', 'localhost'),
                'port': self.elasticsearch_config.get('port', 9200)
            }])
            
            # Initialize incident response orchestrator
            self.orchestrator = IncidentResponseOrchestrator(self.orchestrator_config)
            await self.orchestrator.initialize()
            
            # Initialize evidence collector
            if self.evidence_auto_collect:
                self.evidence_collector = DigitalForensicsEvidenceCollector(self.evidence_collector_config)
                await self.evidence_collector.initialize()
                await self.evidence_collector.start_collection_workers()
            
            # Load trigger rules
            await self._load_trigger_rules()
            
            logger.info("AlertIncidentIntegration initialized successfully",
                       rules=len(self.trigger_rules),
                       evidence_collection=self.evidence_auto_collect)
            
        except Exception as e:
            logger.error("Failed to initialize AlertIncidentIntegration", error=str(e))
            raise
    
    async def start_monitoring(self):
        """Start monitoring alert streams"""
        if self.running:
            return
        
        self.running = True
        
        # Start alert stream monitors
        monitor_tasks = []
        for stream_key in self.alert_stream_keys:
            task = asyncio.create_task(self._monitor_alert_stream(stream_key))
            monitor_tasks.append(task)
        
        # Start correlation cleanup task
        cleanup_task = asyncio.create_task(self._cleanup_old_correlations())
        monitor_tasks.append(cleanup_task)
        
        logger.info("Alert monitoring started", streams=len(self.alert_stream_keys))
        
        # Wait for all tasks to complete (should run indefinitely)
        await asyncio.gather(*monitor_tasks, return_exceptions=True)
    
    async def stop_monitoring(self):
        """Stop monitoring alert streams"""
        self.running = False
        logger.info("Alert monitoring stopping")
        
        if self.evidence_collector:
            await self.evidence_collector.stop_collection_workers()
    
    async def _monitor_alert_stream(self, stream_key: str):
        """Monitor a specific alert stream for incidents"""
        last_id = "0"
        
        logger.info("Starting alert stream monitor", stream=stream_key)
        
        while self.running:
            try:
                # Read from Redis stream
                messages = await self.redis_client.xread({stream_key: last_id}, block=1000)
                
                for stream, msgs in messages:
                    for msg_id, alert_data in msgs:
                        last_id = msg_id
                        
                        # Skip if already processed
                        alert_id = alert_data.get('id', msg_id)
                        if alert_id in self.processed_alerts:
                            continue
                        
                        # Process alert for incident response
                        await self._process_alert_for_incident_response(alert_data, stream_key)
                        
                        # Mark as processed
                        self.processed_alerts.add(alert_id)
                        
                        # Limit processed alerts set size
                        if len(self.processed_alerts) > 10000:
                            # Keep only the most recent 5000
                            recent_alerts = list(self.processed_alerts)[-5000:]
                            self.processed_alerts = set(recent_alerts)
                        
            except Exception as e:
                logger.error("Error monitoring alert stream", 
                           stream=stream_key, error=str(e))
                await asyncio.sleep(5)  # Back off on error
    
    async def _process_alert_for_incident_response(self, alert: Dict[str, Any], source_stream: str):
        """Process an individual alert for incident response triggers"""
        start_time = datetime.now(timezone.utc)
        
        try:
            alert_id = alert.get('id', 'unknown')
            
            logger.debug("Processing alert for incident response",
                        alert_id=alert_id,
                        severity=alert.get('severity'),
                        category=alert.get('category'))
            
            # Check if alert matches any trigger rules
            matching_rules = await self._evaluate_trigger_rules(alert)
            
            if not matching_rules:
                ALERTS_PROCESSED_FOR_IR.labels(outcome="no_match").inc()
                return
            
            # Sort rules by priority (lower number = higher priority)
            matching_rules.sort(key=lambda r: r.priority)
            
            # Apply highest priority rule
            selected_rule = matching_rules[0]
            
            logger.info("Alert matched incident response trigger rule",
                       alert_id=alert_id,
                       rule_id=selected_rule.rule_id,
                       rule_name=selected_rule.name)
            
            # Perform correlation analysis
            correlation = await self._perform_alert_correlation(alert)
            
            # Determine if immediate containment is needed
            immediate_containment = (
                selected_rule.immediate_containment or 
                alert.get('severity', '').lower() == 'critical' or
                'ransomware' in alert.get('category', '').lower()
            )
            
            # Trigger incident response
            incident_id = None
            if 'create_incident' in selected_rule.actions:
                incident_id = await self.orchestrator.process_alert_for_incident(alert)
                
                if incident_id:
                    INCIDENT_RESPONSE_TRIGGERED.labels(
                        alert_type=alert.get('category', 'unknown'),
                        severity=alert.get('severity', 'unknown')
                    ).inc()
                    
                    processing_time = (datetime.now(timezone.utc) - start_time).total_seconds()
                    ALERT_TO_INCIDENT_TIME.observe(processing_time)
            
            # Trigger evidence collection if configured
            if selected_rule.evidence_collection and self.evidence_collector and incident_id:
                await self._trigger_evidence_collection(alert, incident_id, selected_rule)
            
            # Store correlation and incident mapping
            if correlation and incident_id:
                await self._store_alert_incident_mapping(alert, correlation, incident_id)
            
            ALERTS_PROCESSED_FOR_IR.labels(outcome="processed").inc()
            
            logger.info("Alert processed for incident response",
                       alert_id=alert_id,
                       incident_id=incident_id,
                       rule_applied=selected_rule.name,
                       immediate_containment=immediate_containment,
                       processing_time=processing_time)
            
        except Exception as e:
            logger.error("Failed to process alert for incident response",
                        alert_id=alert.get('id', 'unknown'),
                        error=str(e))
            ALERTS_PROCESSED_FOR_IR.labels(outcome="error").inc()
    
    async def _evaluate_trigger_rules(self, alert: Dict[str, Any]) -> List[TriggerRule]:
        """Evaluate alert against all trigger rules"""
        matching_rules = []
        
        for rule in self.trigger_rules.values():
            if not rule.enabled:
                continue
            
            if await self._rule_matches_alert(rule, alert):
                matching_rules.append(rule)
        
        return matching_rules
    
    async def _rule_matches_alert(self, rule: TriggerRule, alert: Dict[str, Any]) -> bool:
        """Check if a trigger rule matches an alert"""
        
        try:
            conditions = rule.conditions
            
            # Severity-based matching
            if rule.policy_type == AlertTriggerPolicy.SEVERITY_BASED:
                required_severities = conditions.get('severities', [])
                alert_severity = alert.get('severity', '').lower()
                
                if alert_severity in [s.lower() for s in required_severities]:
                    return True
            
            # Category-based matching
            elif rule.policy_type == AlertTriggerPolicy.CATEGORY_BASED:
                required_categories = conditions.get('categories', [])
                alert_category = alert.get('category', '').lower()
                
                for category in required_categories:
                    if category.lower() in alert_category:
                        return True
            
            # Source-based matching
            elif rule.policy_type == AlertTriggerPolicy.SOURCE_BASED:
                required_sources = conditions.get('sources', [])
                alert_source = alert.get('source', '').lower()
                
                if alert_source in [s.lower() for s in required_sources]:
                    return True
            
            # ML confidence-based matching
            elif rule.policy_type == AlertTriggerPolicy.ML_CONFIDENCE_BASED:
                min_confidence = conditions.get('min_confidence', 0.8)
                alert_confidence = alert.get('confidence', 0)
                
                if alert_confidence >= min_confidence:
                    return True
            
            # Complex condition matching (AND/OR logic)
            elif 'complex_conditions' in conditions:
                return await self._evaluate_complex_conditions(conditions['complex_conditions'], alert)
        
        except Exception as e:
            logger.error("Error evaluating trigger rule",
                        rule_id=rule.rule_id,
                        error=str(e))
        
        return False
    
    async def _evaluate_complex_conditions(self, conditions: Dict[str, Any], alert: Dict[str, Any]) -> bool:
        """Evaluate complex AND/OR conditions"""
        
        operator = conditions.get('operator', 'AND').upper()
        rules = conditions.get('rules', [])
        
        if operator == 'AND':
            return all(await self._evaluate_single_condition(rule, alert) for rule in rules)
        elif operator == 'OR':
            return any(await self._evaluate_single_condition(rule, alert) for rule in rules)
        
        return False
    
    async def _evaluate_single_condition(self, condition: Dict[str, Any], alert: Dict[str, Any]) -> bool:
        """Evaluate a single condition"""
        
        field = condition.get('field')
        operator = condition.get('operator', 'equals')
        value = condition.get('value')
        
        if not field or value is None:
            return False
        
        alert_value = alert.get(field)
        
        if operator == 'equals':
            return str(alert_value).lower() == str(value).lower()
        elif operator == 'contains':
            return str(value).lower() in str(alert_value).lower()
        elif operator == 'greater_than':
            return float(alert_value or 0) > float(value)
        elif operator == 'less_than':
            return float(alert_value or 0) < float(value)
        elif operator == 'in':
            return alert_value in value if isinstance(value, list) else False
        
        return False
    
    async def _perform_alert_correlation(self, alert: Dict[str, Any]) -> Optional[AlertCorrelation]:
        """Perform correlation analysis to find related alerts"""
        
        try:
            alert_id = alert.get('id', 'unknown')
            
            # Define correlation criteria
            correlation_fields = [
                'source_ip', 'destination_ip', 'user', 'hostname', 
                'file_hash', 'domain', 'signature'
            ]
            
            # Build correlation query
            must_conditions = []
            for field in correlation_fields:
                if field in alert and alert[field]:
                    must_conditions.append({
                        'term': {f'{field}.keyword': alert[field]}
                    })
            
            if not must_conditions:
                return None
            
            # Search for correlated alerts
            query = {
                'query': {
                    'bool': {
                        'should': must_conditions,
                        'minimum_should_match': 1,
                        'filter': [
                            {
                                'range': {
                                    '@timestamp': {
                                        'gte': f"now-{self.correlation_window_seconds}s"
                                    }
                                }
                            }
                        ]
                    }
                }
            }
            
            response = await self.elasticsearch.search(
                index="soc-alerts-*",
                body=query,
                size=self.max_correlation_alerts
            )
            
            correlated_alerts = []
            correlation_score = 0
            
            for hit in response['hits']['hits']:
                correlated_alert = hit['_source']
                correlated_id = correlated_alert.get('id')
                
                # Don't correlate with self
                if correlated_id == alert_id:
                    continue
                
                # Calculate correlation score based on matching fields
                matches = 0
                for field in correlation_fields:
                    if (field in alert and field in correlated_alert and 
                        alert[field] == correlated_alert[field]):
                        matches += 1
                
                if matches > 0:
                    correlated_alerts.append(correlated_id)
                    correlation_score += matches
            
            if correlated_alerts:
                correlation = AlertCorrelation(
                    correlation_id=str(hash(f"{alert_id}_{'-'.join(sorted(correlated_alerts))}")),
                    primary_alert_id=alert_id,
                    related_alert_ids=correlated_alerts,
                    correlation_score=correlation_score / len(correlated_alerts),
                    correlation_type="field_matching",
                    created_at=datetime.now(timezone.utc)
                )
                
                self.active_correlations[correlation.correlation_id] = correlation
                
                logger.info("Alert correlation found",
                           alert_id=alert_id,
                           correlated_count=len(correlated_alerts),
                           correlation_score=correlation.correlation_score)
                
                return correlation
        
        except Exception as e:
            logger.error("Error performing alert correlation",
                        alert_id=alert.get('id', 'unknown'),
                        error=str(e))
        
        return None
    
    async def _trigger_evidence_collection(self, alert: Dict[str, Any], incident_id: str, rule: TriggerRule):
        """Trigger automated evidence collection based on alert"""
        
        try:
            # Determine evidence types to collect based on alert category
            evidence_requests = []
            
            category = alert.get('category', '').lower()
            
            # Memory dumps for malware/ransomware
            if any(term in category for term in ['malware', 'ransomware', 'trojan']):
                if 'hostname' in alert or 'source_ip' in alert:
                    evidence_requests.append(EvidenceCollectionRequest(
                        request_id=f"mem_{incident_id}_{len(evidence_requests)}",
                        incident_id=incident_id,
                        evidence_type=EvidenceType.MEMORY_DUMP,
                        source_system="endpoint",
                        source_identifier=alert.get('hostname', alert.get('source_ip', 'unknown')),
                        priority=1,  # High priority
                        legal_authorization=True,
                        preservation_order=True
                    ))
            
            # Network captures for network-based incidents
            if any(term in category for term in ['network', 'lateral_movement', 'exfiltration']):
                if 'source_ip' in alert:
                    evidence_requests.append(EvidenceCollectionRequest(
                        request_id=f"pcap_{incident_id}_{len(evidence_requests)}",
                        incident_id=incident_id,
                        evidence_type=EvidenceType.NETWORK_CAPTURE,
                        source_system="network_monitor",
                        source_identifier=alert['source_ip'],
                        priority=2,
                        parameters={'time_window': '2_hours'}
                    ))
            
            # System logs for all incidents
            if alert.get('source'):
                evidence_requests.append(EvidenceCollectionRequest(
                    request_id=f"logs_{incident_id}_{len(evidence_requests)}",
                    incident_id=incident_id,
                    evidence_type=EvidenceType.LOG_FILES,
                    source_system=alert['source'],
                    source_identifier=alert.get('hostname', alert.get('source_ip', alert['source'])),
                    priority=3,
                    parameters={'time_range': '24_hours', 'log_types': ['system', 'security', 'application']}
                ))
            
            # Email messages for phishing incidents
            if 'phishing' in category and 'email_id' in alert:
                evidence_requests.append(EvidenceCollectionRequest(
                    request_id=f"email_{incident_id}_{len(evidence_requests)}",
                    incident_id=incident_id,
                    evidence_type=EvidenceType.EMAIL_MESSAGE,
                    source_system="email_system",
                    source_identifier=alert['email_id'],
                    priority=2
                ))
            
            # Submit evidence collection requests
            for request in evidence_requests:
                evidence_id = await self.evidence_collector.collect_evidence(request)
                
                if evidence_id:
                    logger.info("Evidence collection triggered",
                               evidence_id=evidence_id,
                               type=request.evidence_type.value,
                               incident_id=incident_id)
                else:
                    logger.warning("Evidence collection failed to start",
                                 type=request.evidence_type.value,
                                 incident_id=incident_id)
        
        except Exception as e:
            logger.error("Error triggering evidence collection",
                        incident_id=incident_id,
                        error=str(e))
    
    async def _store_alert_incident_mapping(self, alert: Dict[str, Any], correlation: AlertCorrelation, incident_id: str):
        """Store the mapping between alerts, correlations, and incidents"""
        
        try:
            mapping_doc = {
                'alert_id': alert.get('id'),
                'incident_id': incident_id,
                'correlation_id': correlation.correlation_id if correlation else None,
                'correlation_score': correlation.correlation_score if correlation else 0,
                'related_alerts_count': len(correlation.related_alert_ids) if correlation else 0,
                'alert_severity': alert.get('severity'),
                'alert_category': alert.get('category'),
                'created_at': datetime.now(timezone.utc).isoformat(),
                '@timestamp': datetime.now(timezone.utc).isoformat()
            }
            
            await self.elasticsearch.index(
                index=f"soc-alert-incident-mapping-{datetime.now().strftime('%Y-%m')}",
                body=mapping_doc
            )
            
        except Exception as e:
            logger.error("Error storing alert-incident mapping",
                        alert_id=alert.get('id', 'unknown'),
                        incident_id=incident_id,
                        error=str(e))
    
    async def _cleanup_old_correlations(self):
        """Clean up old correlation data"""
        while self.running:
            try:
                current_time = datetime.now(timezone.utc)
                cutoff_time = current_time.timestamp() - (self.correlation_window_seconds * 2)
                
                # Remove old correlations
                expired_correlations = [
                    corr_id for corr_id, correlation in self.active_correlations.items()
                    if correlation.created_at.timestamp() < cutoff_time
                ]
                
                for corr_id in expired_correlations:
                    del self.active_correlations[corr_id]
                
                if expired_correlations:
                    logger.debug("Cleaned up old correlations", count=len(expired_correlations))
                
                # Sleep for 5 minutes
                await asyncio.sleep(300)
                
            except Exception as e:
                logger.error("Error in correlation cleanup", error=str(e))
                await asyncio.sleep(60)  # Back off on error
    
    async def _load_trigger_rules(self):
        """Load incident response trigger rules"""
        
        # Critical severity rule
        critical_rule = TriggerRule(
            rule_id="critical_severity",
            name="Critical Severity Incidents",
            description="Trigger incident response for all critical severity alerts",
            policy_type=AlertTriggerPolicy.SEVERITY_BASED,
            conditions={'severities': ['critical']},
            actions=['create_incident'],
            priority=1,
            evidence_collection=True,
            immediate_containment=True
        )
        
        # Malware detection rule
        malware_rule = TriggerRule(
            rule_id="malware_detection",
            name="Malware Detection",
            description="Trigger incident response for malware detections",
            policy_type=AlertTriggerPolicy.CATEGORY_BASED,
            conditions={'categories': ['malware', 'ransomware', 'trojan', 'virus']},
            actions=['create_incident'],
            priority=1,
            evidence_collection=True,
            immediate_containment=True
        )
        
        # Data breach rule
        data_breach_rule = TriggerRule(
            rule_id="data_breach",
            name="Data Breach Detection",
            description="Trigger incident response for data breach indicators",
            policy_type=AlertTriggerPolicy.CATEGORY_BASED,
            conditions={'categories': ['data_breach', 'data_exfiltration', 'unauthorized_access']},
            actions=['create_incident'],
            priority=1,
            evidence_collection=True,
            immediate_containment=True
        )
        
        # High confidence ML alerts
        ml_confidence_rule = TriggerRule(
            rule_id="high_confidence_ml",
            name="High Confidence ML Alerts",
            description="Trigger incident response for high confidence ML detections",
            policy_type=AlertTriggerPolicy.ML_CONFIDENCE_BASED,
            conditions={'min_confidence': 0.85},
            actions=['create_incident'],
            priority=2,
            evidence_collection=True
        )
        
        # Privilege escalation rule
        privesc_rule = TriggerRule(
            rule_id="privilege_escalation",
            name="Privilege Escalation",
            description="Trigger incident response for privilege escalation attempts",
            policy_type=AlertTriggerPolicy.CATEGORY_BASED,
            conditions={'categories': ['privilege_escalation', 'elevation_of_privilege']},
            actions=['create_incident'],
            priority=2,
            evidence_collection=True
        )
        
        # DDoS attack rule
        ddos_rule = TriggerRule(
            rule_id="ddos_attack",
            name="DDoS Attack Detection",
            description="Trigger incident response for DDoS attacks",
            policy_type=AlertTriggerPolicy.CATEGORY_BASED,
            conditions={'categories': ['ddos', 'denial_of_service']},
            actions=['create_incident'],
            priority=1,
            immediate_containment=True
        )
        
        # Store rules
        rules = [critical_rule, malware_rule, data_breach_rule, ml_confidence_rule, privesc_rule, ddos_rule]
        
        for rule in rules:
            self.trigger_rules[rule.rule_id] = rule
        
        logger.info("Trigger rules loaded", count=len(self.trigger_rules))
    
    # Public API methods
    async def get_trigger_rules(self) -> List[TriggerRule]:
        """Get all trigger rules"""
        return list(self.trigger_rules.values())
    
    async def add_trigger_rule(self, rule: TriggerRule) -> bool:
        """Add a new trigger rule"""
        try:
            self.trigger_rules[rule.rule_id] = rule
            logger.info("Trigger rule added", rule_id=rule.rule_id, name=rule.name)
            return True
        except Exception as e:
            logger.error("Failed to add trigger rule", rule_id=rule.rule_id, error=str(e))
            return False
    
    async def remove_trigger_rule(self, rule_id: str) -> bool:
        """Remove a trigger rule"""
        try:
            if rule_id in self.trigger_rules:
                del self.trigger_rules[rule_id]
                logger.info("Trigger rule removed", rule_id=rule_id)
                return True
            return False
        except Exception as e:
            logger.error("Failed to remove trigger rule", rule_id=rule_id, error=str(e))
            return False
    
    async def get_correlation_statistics(self) -> Dict[str, Any]:
        """Get correlation statistics"""
        return {
            'active_correlations': len(self.active_correlations),
            'correlation_window_seconds': self.correlation_window_seconds,
            'max_correlation_alerts': self.max_correlation_alerts,
            'processed_alerts': len(self.processed_alerts)
        }