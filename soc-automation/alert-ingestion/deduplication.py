"""
Alert Deduplication Engine - Intelligent duplicate alert detection and filtering

Implements sophisticated deduplication logic to reduce alert noise and prevent
duplicate alert processing while preserving important security information.
"""

import asyncio
import json
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Set
from dataclasses import dataclass, field
from enum import Enum
import redis.asyncio as redis
import structlog

logger = structlog.get_logger(__name__)

class DeduplicationStrategy(Enum):
    """Deduplication strategy types"""
    EXACT_MATCH = "exact_match"
    FIELD_BASED = "field_based"
    FUZZY_MATCH = "fuzzy_match"
    TIME_WINDOW = "time_window"
    SIGNATURE_BASED = "signature_based"

class DeduplicationAction(Enum):
    """Actions to take for duplicate alerts"""
    DROP = "drop"
    MERGE = "merge"
    UPDATE_COUNT = "update_count"
    ESCALATE = "escalate"

@dataclass
class DeduplicationRule:
    """Configuration for a deduplication rule"""
    name: str
    strategy: DeduplicationStrategy
    fields: List[str]
    time_window: int  # seconds
    action: DeduplicationAction
    priority: int = 1
    enabled: bool = True
    conditions: Dict[str, Any] = field(default_factory=dict)
    
class DeduplicationEngine:
    """
    Intelligent alert deduplication engine that identifies and handles
    duplicate alerts using multiple strategies and configurable rules.
    
    Features:
    - Multiple deduplication strategies
    - Time-window based grouping
    - Field-based similarity detection
    - Fuzzy matching for near-duplicates
    - Configurable deduplication rules
    - Alert correlation and merging
    - Statistics and reporting
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        
        # Configuration
        self.default_window = self.config.get('default_time_window', 3600)  # 1 hour
        self.max_duplicates = self.config.get('max_duplicates_per_group', 1000)
        self.cleanup_interval = self.config.get('cleanup_interval', 3600)  # 1 hour
        self.retention_days = self.config.get('retention_days', 7)
        
        # Redis configuration
        self.redis_prefix = self.config.get('redis_prefix', 'soc:dedup')
        self.redis_client: Optional[redis.Redis] = None
        
        # Deduplication rules
        self.rules = self._initialize_default_rules()
        
        # Statistics
        self.stats = {
            'total_processed': 0,
            'duplicates_found': 0,
            'duplicates_dropped': 0,
            'duplicates_merged': 0,
            'rules_matched': {}
        }
        
        # Cleanup task
        self.cleanup_task: Optional[asyncio.Task] = None
        
        logger.info("DeduplicationEngine initialized",
                   default_window=self.default_window,
                   max_duplicates=self.max_duplicates,
                   rules=len(self.rules))
    
    async def initialize(self, redis_client: redis.Redis, time_window: int = None):
        """Initialize deduplication engine with Redis connection"""
        try:
            self.redis_client = redis_client
            if time_window:
                self.default_window = time_window
            
            # Test Redis connection
            await self.redis_client.ping()
            
            # Start cleanup task
            self.cleanup_task = asyncio.create_task(self._cleanup_loop())
            
            logger.info("DeduplicationEngine initialized with Redis")
            
        except Exception as e:
            logger.error("Failed to initialize DeduplicationEngine", error=str(e))
            raise
    
    async def close(self):
        """Close deduplication engine and cleanup"""
        if self.cleanup_task:
            self.cleanup_task.cancel()
            try:
                await self.cleanup_task
            except asyncio.CancelledError:
                pass
        
        logger.info("DeduplicationEngine closed")
    
    async def is_duplicate(self, dedup_hash: str) -> bool:
        """
        Check if an alert hash represents a duplicate
        
        Args:
            dedup_hash: Hash string for the alert
            
        Returns:
            True if the alert is a duplicate, False otherwise
        """
        try:
            self.stats['total_processed'] += 1
            
            if not self.redis_client:
                logger.warning("Redis client not initialized, skipping deduplication")
                return False
            
            # Check if hash exists in Redis
            key = f"{self.redis_prefix}:hash:{dedup_hash}"
            exists = await self.redis_client.exists(key)
            
            if exists:
                self.stats['duplicates_found'] += 1
                
                # Get existing data
                data = await self.redis_client.hgetall(key)
                count = int(data.get('count', '0'))
                
                # Increment count
                await self.redis_client.hincrby(key, 'count', 1)
                await self.redis_client.hset(key, 'last_seen', datetime.now(timezone.utc).isoformat())
                
                # Update TTL
                await self.redis_client.expire(key, self.default_window)
                
                logger.debug("Duplicate alert detected",
                           hash=dedup_hash[:8],
                           count=count + 1)
                
                return True
            
            return False
            
        except Exception as e:
            logger.error("Error checking duplicate", hash=dedup_hash[:8], error=str(e))
            return False
    
    async def mark_seen(self, dedup_hash: str, alert_data: Dict[str, Any] = None):
        """
        Mark an alert hash as seen
        
        Args:
            dedup_hash: Hash string for the alert
            alert_data: Optional alert data for context
        """
        try:
            if not self.redis_client:
                return
            
            key = f"{self.redis_prefix}:hash:{dedup_hash}"
            timestamp = datetime.now(timezone.utc).isoformat()
            
            # Store hash with metadata
            data = {
                'hash': dedup_hash,
                'first_seen': timestamp,
                'last_seen': timestamp,
                'count': 1
            }
            
            if alert_data:
                data.update({
                    'alert_id': alert_data.get('alert_id', ''),
                    'source': alert_data.get('source', ''),
                    'alert_type': alert_data.get('alert_type', ''),
                    'severity': alert_data.get('severity', ''),
                })
            
            await self.redis_client.hset(key, mapping=data)
            await self.redis_client.expire(key, self.default_window)
            
            # Add to time-based index for cleanup
            time_key = f"{self.redis_prefix}:time:{int(datetime.now(timezone.utc).timestamp())}"
            await self.redis_client.sadd(time_key, dedup_hash)
            await self.redis_client.expire(time_key, self.retention_days * 86400)
            
        except Exception as e:
            logger.error("Error marking hash as seen", hash=dedup_hash[:8], error=str(e))
    
    async def get_duplicate_info(self, dedup_hash: str) -> Optional[Dict[str, Any]]:
        """Get information about a duplicate alert"""
        try:
            if not self.redis_client:
                return None
            
            key = f"{self.redis_prefix}:hash:{dedup_hash}"
            data = await self.redis_client.hgetall(key)
            
            if data:
                return {
                    'hash': data.get('hash', ''),
                    'first_seen': data.get('first_seen', ''),
                    'last_seen': data.get('last_seen', ''),
                    'count': int(data.get('count', '0')),
                    'alert_id': data.get('alert_id', ''),
                    'source': data.get('source', ''),
                    'alert_type': data.get('alert_type', ''),
                    'severity': data.get('severity', '')
                }
            
            return None
            
        except Exception as e:
            logger.error("Error getting duplicate info", hash=dedup_hash[:8], error=str(e))
            return None
    
    def calculate_hash(self, alert: Dict[str, Any], rule: DeduplicationRule = None) -> str:
        """
        Calculate deduplication hash for an alert
        
        Args:
            alert: Normalized alert data
            rule: Specific deduplication rule to apply
            
        Returns:
            Hash string for deduplication
        """
        try:
            if rule:
                return self._calculate_rule_based_hash(alert, rule)
            else:
                return self._calculate_default_hash(alert)
                
        except Exception as e:
            logger.error("Error calculating hash", error=str(e))
            # Fallback to simple hash
            content = json.dumps(alert, sort_keys=True)
            return hashlib.sha256(content.encode()).hexdigest()
    
    def _calculate_default_hash(self, alert: Dict[str, Any]) -> str:
        """Calculate hash using default fields"""
        hash_fields = {
            'source_ip': alert.get('source_ip'),
            'destination_ip': alert.get('destination_ip'),
            'alert_type': alert.get('alert_type'),
            'signature': alert.get('signature'),
            'rule_id': alert.get('rule_id'),
            'hostname': alert.get('hostname'),
            'user': alert.get('user')
        }
        
        # Remove None values
        hash_fields = {k: v for k, v in hash_fields.items() if v is not None}
        
        # Add time window for temporal grouping
        if alert.get('timestamp'):
            try:
                if isinstance(alert['timestamp'], str):
                    timestamp = datetime.fromisoformat(alert['timestamp'].replace('Z', '+00:00'))
                else:
                    timestamp = alert['timestamp']
                
                # Round to nearest hour for time-based grouping
                time_window = timestamp.replace(minute=0, second=0, microsecond=0)
                hash_fields['time_window'] = time_window.isoformat()
            except Exception:
                pass
        
        content = json.dumps(hash_fields, sort_keys=True)
        return hashlib.sha256(content.encode()).hexdigest()
    
    def _calculate_rule_based_hash(self, alert: Dict[str, Any], rule: DeduplicationRule) -> str:
        """Calculate hash based on specific rule"""
        if rule.strategy == DeduplicationStrategy.EXACT_MATCH:
            return self._exact_match_hash(alert, rule)
        elif rule.strategy == DeduplicationStrategy.FIELD_BASED:
            return self._field_based_hash(alert, rule)
        elif rule.strategy == DeduplicationStrategy.TIME_WINDOW:
            return self._time_window_hash(alert, rule)
        elif rule.strategy == DeduplicationStrategy.SIGNATURE_BASED:
            return self._signature_based_hash(alert, rule)
        else:
            return self._calculate_default_hash(alert)
    
    def _exact_match_hash(self, alert: Dict[str, Any], rule: DeduplicationRule) -> str:
        """Calculate hash for exact match strategy"""
        content = json.dumps(alert, sort_keys=True)
        return f"exact_{hashlib.sha256(content.encode()).hexdigest()}"
    
    def _field_based_hash(self, alert: Dict[str, Any], rule: DeduplicationRule) -> str:
        """Calculate hash based on specific fields"""
        hash_fields = {}
        for field in rule.fields:
            if field in alert:
                hash_fields[field] = alert[field]
        
        content = json.dumps(hash_fields, sort_keys=True)
        return f"field_{rule.name}_{hashlib.sha256(content.encode()).hexdigest()}"
    
    def _time_window_hash(self, alert: Dict[str, Any], rule: DeduplicationRule) -> str:
        """Calculate hash with time window grouping"""
        hash_fields = {}
        for field in rule.fields:
            if field in alert:
                hash_fields[field] = alert[field]
        
        # Add time window
        if alert.get('timestamp'):
            try:
                if isinstance(alert['timestamp'], str):
                    timestamp = datetime.fromisoformat(alert['timestamp'].replace('Z', '+00:00'))
                else:
                    timestamp = alert['timestamp']
                
                # Round to time window
                window_seconds = rule.time_window
                window_start = timestamp.replace(second=0, microsecond=0)
                window_start = window_start.replace(
                    minute=(window_start.minute // (window_seconds // 60)) * (window_seconds // 60)
                )
                hash_fields['time_window'] = window_start.isoformat()
            except Exception:
                pass
        
        content = json.dumps(hash_fields, sort_keys=True)
        return f"time_{rule.name}_{hashlib.sha256(content.encode()).hexdigest()}"
    
    def _signature_based_hash(self, alert: Dict[str, Any], rule: DeduplicationRule) -> str:
        """Calculate hash based on alert signature patterns"""
        signature_fields = {
            'signature': alert.get('signature', ''),
            'rule_id': alert.get('rule_id', ''),
            'alert_type': alert.get('alert_type', '')
        }
        
        # Add specific fields from rule
        for field in rule.fields:
            if field in alert:
                signature_fields[field] = alert[field]
        
        content = json.dumps(signature_fields, sort_keys=True)
        return f"sig_{rule.name}_{hashlib.sha256(content.encode()).hexdigest()}"
    
    def _initialize_default_rules(self) -> List[DeduplicationRule]:
        """Initialize default deduplication rules"""
        return [
            # Exact duplicate detection (same alert within 5 minutes)
            DeduplicationRule(
                name="exact_duplicates",
                strategy=DeduplicationStrategy.EXACT_MATCH,
                fields=[],
                time_window=300,  # 5 minutes
                action=DeduplicationAction.DROP,
                priority=1
            ),
            
            # Network-based alerts (same source/dest within 1 hour)
            DeduplicationRule(
                name="network_alerts",
                strategy=DeduplicationStrategy.FIELD_BASED,
                fields=['source_ip', 'destination_ip', 'alert_type', 'signature'],
                time_window=3600,  # 1 hour
                action=DeduplicationAction.UPDATE_COUNT,
                priority=2,
                conditions={
                    'alert_type': ['network_intrusion', 'port_scan', 'brute_force']
                }
            ),
            
            # Malware alerts (same hash/signature within 2 hours)
            DeduplicationRule(
                name="malware_alerts",
                strategy=DeduplicationStrategy.FIELD_BASED,
                fields=['file_hash', 'signature', 'hostname'],
                time_window=7200,  # 2 hours
                action=DeduplicationAction.MERGE,
                priority=3,
                conditions={
                    'category': ['malware', 'virus', 'trojan']
                }
            ),
            
            # User authentication alerts (same user/source within 30 minutes)
            DeduplicationRule(
                name="auth_alerts",
                strategy=DeduplicationStrategy.FIELD_BASED,
                fields=['user', 'source_ip', 'alert_type'],
                time_window=1800,  # 30 minutes
                action=DeduplicationAction.UPDATE_COUNT,
                priority=4,
                conditions={
                    'alert_type': ['failed_login', 'account_lockout', 'suspicious_login']
                }
            ),
            
            # System anomaly alerts (same host/type within 1 hour)
            DeduplicationRule(
                name="system_anomalies",
                strategy=DeduplicationStrategy.FIELD_BASED,
                fields=['hostname', 'alert_type', 'process'],
                time_window=3600,  # 1 hour
                action=DeduplicationAction.UPDATE_COUNT,
                priority=5,
                conditions={
                    'category': ['system_anomaly', 'process_anomaly']
                }
            ),
            
            # Signature-based alerts (same rule within 4 hours)
            DeduplicationRule(
                name="signature_alerts",
                strategy=DeduplicationStrategy.SIGNATURE_BASED,
                fields=['rule_id'],
                time_window=14400,  # 4 hours
                action=DeduplicationAction.UPDATE_COUNT,
                priority=6
            )
        ]
    
    def add_rule(self, rule: DeduplicationRule):
        """Add a new deduplication rule"""
        # Insert rule in priority order
        inserted = False
        for i, existing_rule in enumerate(self.rules):
            if rule.priority < existing_rule.priority:
                self.rules.insert(i, rule)
                inserted = True
                break
        
        if not inserted:
            self.rules.append(rule)
        
        logger.info("Deduplication rule added", name=rule.name, priority=rule.priority)
    
    def remove_rule(self, rule_name: str) -> bool:
        """Remove a deduplication rule by name"""
        for i, rule in enumerate(self.rules):
            if rule.name == rule_name:
                del self.rules[i]
                logger.info("Deduplication rule removed", name=rule_name)
                return True
        
        logger.warning("Deduplication rule not found", name=rule_name)
        return False
    
    def get_matching_rule(self, alert: Dict[str, Any]) -> Optional[DeduplicationRule]:
        """Find the first matching deduplication rule for an alert"""
        for rule in self.rules:
            if not rule.enabled:
                continue
            
            # Check rule conditions
            if rule.conditions:
                match = True
                for field, allowed_values in rule.conditions.items():
                    alert_value = alert.get(field)
                    if alert_value not in allowed_values:
                        match = False
                        break
                
                if not match:
                    continue
            
            # Rule matches
            self.stats['rules_matched'][rule.name] = self.stats['rules_matched'].get(rule.name, 0) + 1
            return rule
        
        return None
    
    async def process_duplicate_action(
        self, 
        alert: Dict[str, Any], 
        rule: DeduplicationRule,
        duplicate_info: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Process the action for a duplicate alert"""
        try:
            if rule.action == DeduplicationAction.DROP:
                self.stats['duplicates_dropped'] += 1
                logger.debug("Alert dropped due to deduplication",
                           rule=rule.name,
                           count=duplicate_info['count'])
                return None
            
            elif rule.action == DeduplicationAction.UPDATE_COUNT:
                # Update alert with duplicate count information
                alert['duplicate_info'] = {
                    'is_duplicate': True,
                    'rule_matched': rule.name,
                    'duplicate_count': duplicate_info['count'],
                    'first_seen': duplicate_info['first_seen'],
                    'last_seen': duplicate_info['last_seen']
                }
                return alert
            
            elif rule.action == DeduplicationAction.MERGE:
                # Merge with existing alert data
                self.stats['duplicates_merged'] += 1
                merged_alert = await self._merge_alerts(alert, duplicate_info)
                return merged_alert
            
            elif rule.action == DeduplicationAction.ESCALATE:
                # Escalate if duplicate count exceeds threshold
                threshold = rule.conditions.get('escalation_threshold', 10)
                if duplicate_info['count'] > threshold:
                    alert['escalated'] = True
                    alert['escalation_reason'] = f"Duplicate count ({duplicate_info['count']}) exceeded threshold ({threshold})"
                
                alert['duplicate_info'] = {
                    'is_duplicate': True,
                    'rule_matched': rule.name,
                    'duplicate_count': duplicate_info['count']
                }
                return alert
            
            return alert
            
        except Exception as e:
            logger.error("Error processing duplicate action",
                        rule=rule.name,
                        action=rule.action.value,
                        error=str(e))
            return alert
    
    async def _merge_alerts(self, new_alert: Dict[str, Any], duplicate_info: Dict[str, Any]) -> Dict[str, Any]:
        """Merge new alert with existing duplicate information"""
        merged_alert = new_alert.copy()
        
        # Add merge metadata
        merged_alert['merged_info'] = {
            'is_merged': True,
            'duplicate_count': duplicate_info['count'],
            'first_occurrence': duplicate_info['first_seen'],
            'latest_occurrence': duplicate_info['last_seen'],
            'merge_timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        # Update severity if this is a repeated occurrence
        current_severity = merged_alert.get('severity', 'medium')
        if duplicate_info['count'] > 5:  # Multiple occurrences
            severity_escalation = {
                'low': 'medium',
                'medium': 'high',
                'high': 'critical',
                'critical': 'critical'
            }
            merged_alert['severity'] = severity_escalation.get(current_severity, current_severity)
            merged_alert['severity_escalated'] = True
            merged_alert['escalation_reason'] = f"Repeated occurrence ({duplicate_info['count']} times)"
        
        return merged_alert
    
    async def _cleanup_loop(self):
        """Periodic cleanup of old deduplication data"""
        while True:
            try:
                await asyncio.sleep(self.cleanup_interval)
                await self._cleanup_old_data()
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Cleanup loop error", error=str(e))
    
    async def _cleanup_old_data(self):
        """Clean up old deduplication data from Redis"""
        try:
            if not self.redis_client:
                return
            
            cutoff_time = datetime.now(timezone.utc) - timedelta(days=self.retention_days)
            cutoff_timestamp = int(cutoff_time.timestamp())
            
            # Find old time-based keys
            pattern = f"{self.redis_prefix}:time:*"
            keys = []
            
            async for key in self.redis_client.scan_iter(match=pattern):
                # Extract timestamp from key
                try:
                    timestamp_str = key.split(':')[-1]
                    timestamp = int(timestamp_str)
                    
                    if timestamp < cutoff_timestamp:
                        # Get all hashes for this timestamp
                        hashes = await self.redis_client.smembers(key)
                        
                        # Delete hash keys
                        for hash_value in hashes:
                            hash_key = f"{self.redis_prefix}:hash:{hash_value}"
                            keys.append(hash_key)
                        
                        # Delete time key
                        keys.append(key)
                        
                except (ValueError, IndexError):
                    continue
            
            if keys:
                await self.redis_client.delete(*keys)
                logger.info("Cleaned up old deduplication data", keys_deleted=len(keys))
            
        except Exception as e:
            logger.error("Error during deduplication cleanup", error=str(e))
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get deduplication statistics"""
        return {
            'total_processed': self.stats['total_processed'],
            'duplicates_found': self.stats['duplicates_found'],
            'duplicates_dropped': self.stats['duplicates_dropped'],
            'duplicates_merged': self.stats['duplicates_merged'],
            'duplicate_rate': (
                self.stats['duplicates_found'] / max(self.stats['total_processed'], 1)
            ) * 100,
            'rules_matched': self.stats['rules_matched'].copy(),
            'active_rules': len([r for r in self.rules if r.enabled]),
            'total_rules': len(self.rules)
        }
    
    def reset_statistics(self):
        """Reset deduplication statistics"""
        self.stats = {
            'total_processed': 0,
            'duplicates_found': 0,
            'duplicates_dropped': 0,
            'duplicates_merged': 0,
            'rules_matched': {}
        }
        logger.info("Deduplication statistics reset")
    
    async def get_active_duplicates(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get list of currently active duplicate groups"""
        try:
            if not self.redis_client:
                return []
            
            duplicates = []
            pattern = f"{self.redis_prefix}:hash:*"
            count = 0
            
            async for key in self.redis_client.scan_iter(match=pattern):
                if count >= limit:
                    break
                
                data = await self.redis_client.hgetall(key)
                if data and int(data.get('count', '0')) > 1:
                    duplicates.append({
                        'hash': data.get('hash', ''),
                        'count': int(data.get('count', '0')),
                        'first_seen': data.get('first_seen', ''),
                        'last_seen': data.get('last_seen', ''),
                        'alert_type': data.get('alert_type', ''),
                        'source': data.get('source', ''),
                        'severity': data.get('severity', '')
                    })
                    count += 1
            
            # Sort by count descending
            duplicates.sort(key=lambda x: x['count'], reverse=True)
            return duplicates
            
        except Exception as e:
            logger.error("Error getting active duplicates", error=str(e))
            return []