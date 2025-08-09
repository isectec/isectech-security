"""
Identity Threat Detection Engine
Production-grade threat detection system for sophisticated identity attack pattern recognition in ISECTECH platform
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
from collections import defaultdict, deque
import sqlite3
import aiosqlite
import redis.asyncio as redis
import numpy as np
import pandas as pd
from concurrent.futures import ThreadPoolExecutor
import threading
import math
import re
import ipaddress
from urllib.parse import urlparse
import statistics
from scipy import stats
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler
from sklearn.metrics.pairwise import cosine_similarity
import networkx as nx
import geoip2.database
import requests
import aiohttp
from cryptography.hazmat.primitives import hashes
import base64
import hmac
import secrets


class ThreatType(Enum):
    """Types of identity threats"""
    CREDENTIAL_THEFT = "credential_theft"
    BRUTE_FORCE = "brute_force"
    PASSWORD_SPRAY = "password_spray"
    CREDENTIAL_STUFFING = "credential_stuffing"
    ACCOUNT_TAKEOVER = "account_takeover"
    SESSION_HIJACKING = "session_hijacking"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    APT_BEHAVIOR = "apt_behavior"
    COMPROMISED_ACCOUNT = "compromised_account"
    BOT_ACTIVITY = "bot_activity"
    DISTRIBUTED_ATTACK = "distributed_attack"
    INSIDER_THREAT = "insider_threat"
    SOCIAL_ENGINEERING = "social_engineering"


class ThreatSeverity(Enum):
    """Threat severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AttackStage(Enum):
    """MITRE ATT&CK framework stages"""
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    COMMAND_CONTROL = "command_control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


class ThreatIntelligenceSource(Enum):
    """Threat intelligence sources"""
    INTERNAL = "internal"
    MISP = "misp"
    STIX_TAXII = "stix_taxii"
    COMMERCIAL_FEED = "commercial_feed"
    OPEN_SOURCE = "open_source"
    DARK_WEB = "dark_web"
    HONEYPOT = "honeypot"
    THREAT_HUNTING = "threat_hunting"


@dataclass
class ThreatIndicator:
    """Threat indicator from intelligence sources"""
    indicator_id: str
    indicator_type: str  # ip, domain, hash, email, etc.
    indicator_value: str
    threat_types: List[ThreatType]
    confidence: float  # 0-1 scale
    severity: ThreatSeverity
    source: ThreatIntelligenceSource
    first_seen: datetime
    last_seen: datetime
    description: str
    tags: List[str] = field(default_factory=list)
    ttl_hours: int = 24
    active: bool = True
    metadata: Optional[Dict[str, Any]] = None


@dataclass
class AttackVector:
    """Attack vector information"""
    vector_id: str
    attack_type: ThreatType
    source_ip: Optional[str] = None
    source_country: Optional[str] = None
    target_user: Optional[str] = None
    target_application: Optional[str] = None
    target_resource: Optional[str] = None
    technique_id: Optional[str] = None  # MITRE ATT&CK technique ID
    confidence: float = 0.0
    severity: ThreatSeverity = ThreatSeverity.MEDIUM
    description: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class ThreatEvent:
    """Detected threat event"""
    event_id: str
    threat_type: ThreatType
    severity: ThreatSeverity
    confidence: float
    user_id: str
    source_ip: Optional[str] = None
    user_agent: Optional[str] = None
    session_id: Optional[str] = None
    application: Optional[str] = None
    resource: Optional[str] = None
    attack_stage: Optional[AttackStage] = None
    attack_vectors: List[AttackVector] = field(default_factory=list)
    indicators: List[str] = field(default_factory=list)  # IOC IDs
    description: str = ""
    recommendations: List[str] = field(default_factory=list)
    raw_evidence: Dict[str, Any] = field(default_factory=dict)
    correlated_events: List[str] = field(default_factory=list)
    campaign_id: Optional[str] = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    ttl_hours: int = 168  # 7 days default
    status: str = "active"
    false_positive: bool = False


@dataclass
class ThreatCampaign:
    """Multi-event threat campaign"""
    campaign_id: str
    campaign_name: str
    threat_types: List[ThreatType]
    severity: ThreatSeverity
    confidence: float
    start_time: datetime
    end_time: Optional[datetime] = None
    threat_events: List[str] = field(default_factory=list)  # Event IDs
    affected_users: Set[str] = field(default_factory=set)
    source_ips: Set[str] = field(default_factory=set)
    attack_pattern: str = ""
    threat_actor: Optional[str] = None
    attribution_confidence: float = 0.0
    tactics: List[AttackStage] = field(default_factory=list)
    description: str = ""
    status: str = "active"
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class CredentialTheftDetector:
    """Detector for credential theft and compromise"""
    
    def __init__(self, redis_client: Optional[redis.Redis] = None):
        self.redis_client = redis_client
        self.compromised_patterns = {
            'impossible_travel': 0.8,
            'new_device_high_privilege': 0.7,
            'off_hours_admin_access': 0.6,
            'multiple_failed_then_success': 0.9,
            'password_spray_followed_by_access': 0.8,
            'geolocation_anomaly': 0.7,
            'behavioral_deviation': 0.6
        }
        
    async def detect_credential_theft(self, events: List[Dict[str, Any]], 
                                    user_profile: Dict[str, Any]) -> List[ThreatEvent]:
        """Detect potential credential theft"""
        threats = []
        
        # Sort events by timestamp
        sorted_events = sorted(events, key=lambda x: x.get('timestamp', ''))
        
        # Check for impossible travel
        travel_threat = await self._detect_impossible_travel(sorted_events, user_profile)
        if travel_threat:
            threats.append(travel_threat)
        
        # Check for compromise indicators
        compromise_threat = await self._detect_account_compromise(sorted_events, user_profile)
        if compromise_threat:
            threats.append(compromise_threat)
        
        # Check for credential stuffing patterns
        stuffing_threat = await self._detect_credential_stuffing(sorted_events, user_profile)
        if stuffing_threat:
            threats.append(stuffing_threat)
        
        return threats
    
    async def _detect_impossible_travel(self, events: List[Dict[str, Any]], 
                                      user_profile: Dict[str, Any]) -> Optional[ThreatEvent]:
        """Detect impossible travel scenarios"""
        if len(events) < 2:
            return None
        
        suspicious_travels = []
        
        for i in range(1, len(events)):
            prev_event = events[i-1]
            curr_event = events[i]
            
            # Extract location info
            prev_location = self._extract_location(prev_event)
            curr_location = self._extract_location(curr_event)
            
            if not prev_location or not curr_location:
                continue
            
            # Calculate time difference
            prev_time = datetime.fromisoformat(prev_event['timestamp'].replace('Z', '+00:00'))
            curr_time = datetime.fromisoformat(curr_event['timestamp'].replace('Z', '+00:00'))
            time_diff_hours = (curr_time - prev_time).total_seconds() / 3600
            
            if time_diff_hours <= 0:
                continue
            
            # Calculate distance
            distance_km = self._haversine_distance(
                prev_location['lat'], prev_location['lon'],
                curr_location['lat'], curr_location['lon']
            )
            
            # Calculate required speed
            if time_diff_hours > 0:
                required_speed = distance_km / time_diff_hours
                max_reasonable_speed = 1000  # km/h including commercial flights
                
                if required_speed > max_reasonable_speed:
                    suspicious_travels.append({
                        'distance_km': distance_km,
                        'time_hours': time_diff_hours,
                        'speed_kmh': required_speed,
                        'from_location': prev_location,
                        'to_location': curr_location,
                        'events': [prev_event, curr_event]
                    })
        
        if suspicious_travels:
            # Create threat event for most suspicious travel
            most_suspicious = max(suspicious_travels, key=lambda x: x['speed_kmh'])
            
            confidence = min(0.95, most_suspicious['speed_kmh'] / 2000)  # Scale confidence
            
            return ThreatEvent(
                event_id=str(uuid.uuid4()),
                threat_type=ThreatType.CREDENTIAL_THEFT,
                severity=ThreatSeverity.HIGH,
                confidence=confidence,
                user_id=user_profile.get('user_id', 'unknown'),
                description=f"Impossible travel detected: {most_suspicious['distance_km']:.1f}km in {most_suspicious['time_hours']:.1f}h (speed: {most_suspicious['speed_kmh']:.1f}km/h)",
                attack_stage=AttackStage.INITIAL_ACCESS,
                attack_vectors=[AttackVector(
                    vector_id=str(uuid.uuid4()),
                    attack_type=ThreatType.CREDENTIAL_THEFT,
                    source_ip=most_suspicious['events'][1].get('source_ip'),
                    confidence=confidence,
                    description="Impossible travel pattern indicating potential credential theft",
                    evidence=most_suspicious
                )],
                recommendations=[
                    "Verify user identity through additional authentication",
                    "Review account access patterns",
                    "Consider temporary account restriction",
                    "Investigate potential credential compromise"
                ],
                raw_evidence={'suspicious_travels': suspicious_travels}
            )
        
        return None
    
    async def _detect_account_compromise(self, events: List[Dict[str, Any]], 
                                       user_profile: Dict[str, Any]) -> Optional[ThreatEvent]:
        """Detect account compromise indicators"""
        compromise_indicators = []
        
        # Check for behavioral anomalies
        behavioral_score = await self._calculate_behavioral_anomaly_score(events, user_profile)
        if behavioral_score > 0.7:
            compromise_indicators.append({
                'type': 'behavioral_anomaly',
                'score': behavioral_score,
                'description': 'Significant deviation from normal user behavior'
            })
        
        # Check for multiple failed attempts followed by success
        failed_success_pattern = self._detect_failed_success_pattern(events)
        if failed_success_pattern:
            compromise_indicators.append({
                'type': 'failed_then_success',
                'score': 0.8,
                'description': 'Multiple failed attempts followed by successful authentication',
                'details': failed_success_pattern
            })
        
        # Check for new device with high privileges
        new_device_privilege = self._detect_new_device_privilege_access(events, user_profile)
        if new_device_privilege:
            compromise_indicators.append({
                'type': 'new_device_privilege',
                'score': 0.7,
                'description': 'High-privilege access from new device',
                'details': new_device_privilege
            })
        
        # Check for off-hours administrative access
        off_hours_admin = self._detect_off_hours_admin_access(events, user_profile)
        if off_hours_admin:
            compromise_indicators.append({
                'type': 'off_hours_admin',
                'score': 0.6,
                'description': 'Administrative access during off-hours',
                'details': off_hours_admin
            })
        
        if compromise_indicators:
            # Calculate overall confidence
            max_score = max(indicator['score'] for indicator in compromise_indicators)
            confidence = min(0.95, max_score)
            
            # Determine severity
            if max_score >= 0.8:
                severity = ThreatSeverity.CRITICAL
            elif max_score >= 0.6:
                severity = ThreatSeverity.HIGH
            else:
                severity = ThreatSeverity.MEDIUM
            
            return ThreatEvent(
                event_id=str(uuid.uuid4()),
                threat_type=ThreatType.COMPROMISED_ACCOUNT,
                severity=severity,
                confidence=confidence,
                user_id=user_profile.get('user_id', 'unknown'),
                description=f"Account compromise indicators detected: {', '.join([i['type'] for i in compromise_indicators])}",
                attack_stage=AttackStage.INITIAL_ACCESS,
                attack_vectors=[AttackVector(
                    vector_id=str(uuid.uuid4()),
                    attack_type=ThreatType.COMPROMISED_ACCOUNT,
                    confidence=confidence,
                    description=indicator['description'],
                    evidence=indicator
                ) for indicator in compromise_indicators],
                recommendations=[
                    "Force password reset for affected user",
                    "Review and revoke suspicious sessions",
                    "Enable additional authentication factors",
                    "Monitor account activity closely",
                    "Review access patterns and permissions"
                ],
                raw_evidence={'compromise_indicators': compromise_indicators}
            )
        
        return None
    
    async def _detect_credential_stuffing(self, events: List[Dict[str, Any]], 
                                        user_profile: Dict[str, Any]) -> Optional[ThreatEvent]:
        """Detect credential stuffing attacks"""
        # Look for patterns indicating credential stuffing
        failed_logins = [e for e in events if not e.get('success', True)]
        successful_logins = [e for e in events if e.get('success', True)]
        
        if len(failed_logins) < 3:
            return None
        
        # Check for rapid failed attempts from same IP
        ip_failures = defaultdict(list)
        for event in failed_logins:
            ip = event.get('source_ip')
            if ip:
                ip_failures[ip].append(event)
        
        stuffing_indicators = []
        
        for ip, failures in ip_failures.items():
            if len(failures) >= 5:  # Multiple failures from same IP
                # Check time window
                timestamps = [datetime.fromisoformat(e['timestamp'].replace('Z', '+00:00')) for e in failures]
                time_span = (max(timestamps) - min(timestamps)).total_seconds()
                
                if time_span < 300:  # 5 minutes
                    failure_rate = len(failures) / (time_span / 60)  # failures per minute
                    
                    if failure_rate > 2:  # More than 2 failures per minute
                        stuffing_indicators.append({
                            'source_ip': ip,
                            'failure_count': len(failures),
                            'time_span_seconds': time_span,
                            'failure_rate_per_minute': failure_rate
                        })
        
        if stuffing_indicators:
            confidence = min(0.9, len(stuffing_indicators) * 0.3)
            
            return ThreatEvent(
                event_id=str(uuid.uuid4()),
                threat_type=ThreatType.CREDENTIAL_STUFFING,
                severity=ThreatSeverity.HIGH,
                confidence=confidence,
                user_id=user_profile.get('user_id', 'unknown'),
                description=f"Credential stuffing attack detected from {len(stuffing_indicators)} IP addresses",
                attack_stage=AttackStage.CREDENTIAL_ACCESS,
                attack_vectors=[AttackVector(
                    vector_id=str(uuid.uuid4()),
                    attack_type=ThreatType.CREDENTIAL_STUFFING,
                    source_ip=indicator['source_ip'],
                    confidence=confidence,
                    description=f"High-frequency login attempts: {indicator['failure_rate_per_minute']:.1f} attempts/min",
                    evidence=indicator
                ) for indicator in stuffing_indicators],
                recommendations=[
                    "Implement rate limiting for authentication attempts",
                    "Block or throttle suspicious IP addresses",
                    "Enable CAPTCHA after failed attempts",
                    "Monitor for successful logins after stuffing attempts",
                    "Consider geo-blocking if attacks from specific regions"
                ],
                raw_evidence={'stuffing_indicators': stuffing_indicators}
            )
        
        return None
    
    def _extract_location(self, event: Dict[str, Any]) -> Optional[Dict[str, float]]:
        """Extract location information from event"""
        lat = event.get('latitude') or event.get('geo_location', {}).get('latitude')
        lon = event.get('longitude') or event.get('geo_location', {}).get('longitude')
        
        if lat is not None and lon is not None:
            return {'lat': float(lat), 'lon': float(lon)}
        
        return None
    
    def _haversine_distance(self, lat1: float, lon1: float, lat2: float, lon2: float) -> float:
        """Calculate haversine distance between two points"""
        R = 6371  # Earth's radius in kilometers
        
        lat1_rad = math.radians(lat1)
        lon1_rad = math.radians(lon1)
        lat2_rad = math.radians(lat2)
        lon2_rad = math.radians(lon2)
        
        dlat = lat2_rad - lat1_rad
        dlon = lon2_rad - lon1_rad
        
        a = math.sin(dlat/2)**2 + math.cos(lat1_rad) * math.cos(lat2_rad) * math.sin(dlon/2)**2
        c = 2 * math.asin(math.sqrt(a))
        
        return R * c
    
    async def _calculate_behavioral_anomaly_score(self, events: List[Dict[str, Any]], 
                                                user_profile: Dict[str, Any]) -> float:
        """Calculate behavioral anomaly score"""
        if not events:
            return 0.0
        
        anomaly_factors = []
        
        # Check access time patterns
        access_times = []
        for event in events:
            timestamp = datetime.fromisoformat(event['timestamp'].replace('Z', '+00:00'))
            access_times.append(timestamp.hour)
        
        if access_times:
            # Compare to user's normal hours
            normal_hours = user_profile.get('normal_access_hours', list(range(8, 18)))
            unusual_hours = [h for h in access_times if h not in normal_hours]
            
            if unusual_hours:
                anomaly_factors.append(len(unusual_hours) / len(access_times))
        
        # Check application usage patterns
        applications = [e.get('application') for e in events if e.get('application')]
        if applications:
            normal_apps = user_profile.get('normal_applications', [])
            unusual_apps = [a for a in applications if a not in normal_apps]
            
            if unusual_apps:
                anomaly_factors.append(len(unusual_apps) / len(applications))
        
        # Return average anomaly score
        return statistics.mean(anomaly_factors) if anomaly_factors else 0.0
    
    def _detect_failed_success_pattern(self, events: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Detect pattern of failed attempts followed by success"""
        consecutive_failures = 0
        max_consecutive_failures = 0
        success_after_failures = False
        
        for event in events:
            if event.get('success', True):
                if consecutive_failures >= 3:
                    success_after_failures = True
                consecutive_failures = 0
            else:
                consecutive_failures += 1
                max_consecutive_failures = max(max_consecutive_failures, consecutive_failures)
        
        if success_after_failures and max_consecutive_failures >= 3:
            return {
                'max_consecutive_failures': max_consecutive_failures,
                'success_after_failures': True
            }
        
        return None
    
    def _detect_new_device_privilege_access(self, events: List[Dict[str, Any]], 
                                          user_profile: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Detect high privilege access from new device"""
        known_devices = set(user_profile.get('known_devices', []))
        
        for event in events:
            device_id = event.get('device_id')
            if device_id and device_id not in known_devices:
                # Check if this is a privileged action
                action = event.get('action', '').lower()
                resource = event.get('resource', '').lower()
                
                privileged_actions = ['admin', 'create', 'delete', 'modify', 'escalate']
                privileged_resources = ['admin', 'system', 'config', 'user']
                
                if (any(pa in action for pa in privileged_actions) or 
                    any(pr in resource for pr in privileged_resources)):
                    return {
                        'device_id': device_id,
                        'action': action,
                        'resource': resource,
                        'timestamp': event.get('timestamp')
                    }
        
        return None
    
    def _detect_off_hours_admin_access(self, events: List[Dict[str, Any]], 
                                     user_profile: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Detect administrative access during off-hours"""
        business_hours = user_profile.get('business_hours', {'start': 8, 'end': 18})
        
        for event in events:
            timestamp = datetime.fromisoformat(event['timestamp'].replace('Z', '+00:00'))
            hour = timestamp.hour
            
            if hour < business_hours['start'] or hour >= business_hours['end']:
                # Check if this is an administrative action
                action = event.get('action', '').lower()
                resource = event.get('resource', '').lower()
                roles = event.get('user_roles', [])
                
                admin_indicators = ['admin', 'root', 'superuser', 'system']
                
                if (any(ai in action for ai in admin_indicators) or
                    any(ai in resource for ai in admin_indicators) or
                    any(ai in str(role).lower() for role in roles for ai in admin_indicators)):
                    return {
                        'timestamp': event.get('timestamp'),
                        'hour': hour,
                        'action': action,
                        'resource': resource,
                        'roles': roles
                    }
        
        return None


class BruteForceDetector:
    """Detector for brute force attacks"""
    
    def __init__(self, redis_client: Optional[redis.Redis] = None):
        self.redis_client = redis_client
        self.thresholds = {
            'single_ip_failures': 10,
            'single_user_failures': 15,
            'distributed_threshold': 5,
            'time_window_minutes': 15,
            'velocity_threshold': 5  # attempts per minute
        }
    
    async def detect_brute_force(self, events: List[Dict[str, Any]]) -> List[ThreatEvent]:
        """Detect brute force attacks"""
        threats = []
        
        # Group events by source IP and user
        ip_events = defaultdict(list)
        user_events = defaultdict(list)
        
        for event in events:
            if not event.get('success', True):  # Failed authentication
                ip = event.get('source_ip')
                user = event.get('user_id')
                
                if ip:
                    ip_events[ip].append(event)
                if user:
                    user_events[user].append(event)
        
        # Detect single-source brute force
        for ip, failed_events in ip_events.items():
            if len(failed_events) >= self.thresholds['single_ip_failures']:
                threat = await self._create_brute_force_threat(failed_events, 'single_ip', ip)
                if threat:
                    threats.append(threat)
        
        # Detect user-targeted brute force
        for user, failed_events in user_events.items():
            if len(failed_events) >= self.thresholds['single_user_failures']:
                threat = await self._create_brute_force_threat(failed_events, 'user_targeted', user)
                if threat:
                    threats.append(threat)
        
        # Detect distributed brute force
        distributed_threat = await self._detect_distributed_brute_force(ip_events)
        if distributed_threat:
            threats.append(distributed_threat)
        
        return threats
    
    async def _create_brute_force_threat(self, events: List[Dict[str, Any]], 
                                       attack_type: str, target: str) -> Optional[ThreatEvent]:
        """Create brute force threat event"""
        if not events:
            return None
        
        # Calculate attack velocity
        timestamps = [datetime.fromisoformat(e['timestamp'].replace('Z', '+00:00')) for e in events]
        time_span = (max(timestamps) - min(timestamps)).total_seconds()
        velocity = len(events) / max(time_span / 60, 1)  # attempts per minute
        
        # Calculate confidence based on velocity and count
        confidence = min(0.95, (len(events) / 20) + (velocity / 10))
        
        # Determine severity
        if len(events) >= 50 or velocity >= 10:
            severity = ThreatSeverity.CRITICAL
        elif len(events) >= 20 or velocity >= 5:
            severity = ThreatSeverity.HIGH
        else:
            severity = ThreatSeverity.MEDIUM
        
        # Extract unique source IPs and users
        source_ips = list(set(e.get('source_ip') for e in events if e.get('source_ip')))
        users = list(set(e.get('user_id') for e in events if e.get('user_id')))
        
        description = f"Brute force attack detected ({attack_type}): {len(events)} failed attempts"
        if attack_type == 'single_ip':
            description += f" from IP {target}"
        elif attack_type == 'user_targeted':
            description += f" targeting user {target}"
        
        return ThreatEvent(
            event_id=str(uuid.uuid4()),
            threat_type=ThreatType.BRUTE_FORCE,
            severity=severity,
            confidence=confidence,
            user_id=users[0] if users else 'multiple',
            source_ip=source_ips[0] if len(source_ips) == 1 else None,
            description=description,
            attack_stage=AttackStage.CREDENTIAL_ACCESS,
            attack_vectors=[AttackVector(
                vector_id=str(uuid.uuid4()),
                attack_type=ThreatType.BRUTE_FORCE,
                source_ip=ip,
                target_user=target if attack_type == 'user_targeted' else None,
                confidence=confidence,
                description=f"Brute force attack vector: {len([e for e in events if e.get('source_ip') == ip])} attempts",
                evidence={'attempts': len([e for e in events if e.get('source_ip') == ip])}
            ) for ip in source_ips[:5]],  # Limit to top 5 IPs
            recommendations=[
                "Implement account lockout policies",
                "Enable rate limiting for authentication endpoints",
                "Block or throttle malicious IP addresses",
                "Deploy CAPTCHA after failed attempts",
                "Monitor for successful authentications after attacks",
                "Consider IP reputation filtering"
            ],
            raw_evidence={
                'total_attempts': len(events),
                'unique_ips': len(source_ips),
                'unique_users': len(users),
                'attack_velocity': velocity,
                'time_span_seconds': time_span
            }
        )
    
    async def _detect_distributed_brute_force(self, ip_events: Dict[str, List[Dict[str, Any]]]) -> Optional[ThreatEvent]:
        """Detect distributed brute force attacks"""
        # Look for coordinated attacks from multiple IPs
        coordinated_ips = []
        
        for ip, events in ip_events.items():
            if len(events) >= self.thresholds['distributed_threshold']:
                coordinated_ips.append({
                    'ip': ip,
                    'attempts': len(events),
                    'events': events
                })
        
        if len(coordinated_ips) >= 3:  # At least 3 IPs in coordination
            # Check if attacks are time-correlated
            all_timestamps = []
            for ip_data in coordinated_ips:
                for event in ip_data['events']:
                    all_timestamps.append(datetime.fromisoformat(event['timestamp'].replace('Z', '+00:00')))
            
            if all_timestamps:
                time_span = (max(all_timestamps) - min(all_timestamps)).total_seconds()
                total_attempts = sum(ip_data['attempts'] for ip_data in coordinated_ips)
                
                if time_span < 3600:  # Within 1 hour
                    confidence = min(0.95, len(coordinated_ips) * 0.2)
                    
                    return ThreatEvent(
                        event_id=str(uuid.uuid4()),
                        threat_type=ThreatType.DISTRIBUTED_ATTACK,
                        severity=ThreatSeverity.HIGH,
                        confidence=confidence,
                        user_id='multiple',
                        description=f"Distributed brute force attack from {len(coordinated_ips)} IP addresses ({total_attempts} total attempts)",
                        attack_stage=AttackStage.CREDENTIAL_ACCESS,
                        attack_vectors=[AttackVector(
                            vector_id=str(uuid.uuid4()),
                            attack_type=ThreatType.DISTRIBUTED_ATTACK,
                            source_ip=ip_data['ip'],
                            confidence=confidence,
                            description=f"Coordinated attack vector: {ip_data['attempts']} attempts",
                            evidence=ip_data
                        ) for ip_data in coordinated_ips[:10]],  # Limit to top 10
                        recommendations=[
                            "Implement distributed rate limiting",
                            "Deploy DDoS protection mechanisms",
                            "Use IP reputation and geo-blocking",
                            "Coordinate response across all attack vectors",
                            "Monitor for attack pattern evolution",
                            "Consider emergency authentication restrictions"
                        ],
                        raw_evidence={
                            'coordinated_ips': len(coordinated_ips),
                            'total_attempts': total_attempts,
                            'attack_duration_seconds': time_span,
                            'ip_details': coordinated_ips
                        }
                    )
        
        return None


class SessionHijackingDetector:
    """Detector for session hijacking and anomalies"""
    
    def __init__(self, redis_client: Optional[redis.Redis] = None):
        self.redis_client = redis_client
    
    async def detect_session_hijacking(self, session_events: List[Dict[str, Any]], 
                                     user_profile: Dict[str, Any]) -> List[ThreatEvent]:
        """Detect potential session hijacking"""
        threats = []
        
        # Group events by session ID
        sessions = defaultdict(list)
        for event in session_events:
            session_id = event.get('session_id')
            if session_id:
                sessions[session_id].append(event)
        
        for session_id, events in sessions.items():
            # Check for session anomalies
            hijack_threat = await self._detect_session_anomalies(session_id, events, user_profile)
            if hijack_threat:
                threats.append(hijack_threat)
            
            # Check for concurrent session abuse
            concurrent_threat = await self._detect_concurrent_session_abuse(session_id, events, user_profile)
            if concurrent_threat:
                threats.append(concurrent_threat)
        
        return threats
    
    async def _detect_session_anomalies(self, session_id: str, events: List[Dict[str, Any]], 
                                      user_profile: Dict[str, Any]) -> Optional[ThreatEvent]:
        """Detect anomalies within a session"""
        if len(events) < 2:
            return None
        
        anomalies = []
        
        # Check for IP address changes within session
        ips = [e.get('source_ip') for e in events if e.get('source_ip')]
        unique_ips = list(set(ips))
        
        if len(unique_ips) > 1:
            anomalies.append({
                'type': 'ip_change',
                'severity': 0.8,
                'description': f"Session IP changed from {unique_ips[0]} to {unique_ips[-1]}",
                'details': {'ip_changes': unique_ips}
            })
        
        # Check for user agent changes
        user_agents = [e.get('user_agent') for e in events if e.get('user_agent')]
        unique_agents = list(set(user_agents))
        
        if len(unique_agents) > 1:
            anomalies.append({
                'type': 'user_agent_change',
                'severity': 0.6,
                'description': f"User agent changed within session",
                'details': {'user_agent_changes': unique_agents}
            })
        
        # Check for geolocation jumps
        locations = []
        for event in events:
            location = self._extract_location(event)
            if location:
                locations.append(location)
        
        if len(locations) >= 2:
            for i in range(1, len(locations)):
                distance = self._haversine_distance(
                    locations[i-1]['lat'], locations[i-1]['lon'],
                    locations[i]['lat'], locations[i]['lon']
                )
                
                if distance > 100:  # More than 100km apart
                    anomalies.append({
                        'type': 'location_jump',
                        'severity': 0.9,
                        'description': f"Geographic jump of {distance:.1f}km within session",
                        'details': {'distance_km': distance, 'locations': locations}
                    })
                    break
        
        # Check for behavior pattern changes
        behavior_change = await self._detect_behavior_pattern_change(events, user_profile)
        if behavior_change:
            anomalies.append(behavior_change)
        
        if anomalies:
            max_severity = max(a['severity'] for a in anomalies)
            confidence = min(0.95, max_severity)
            
            severity = ThreatSeverity.CRITICAL if max_severity >= 0.8 else ThreatSeverity.HIGH
            
            return ThreatEvent(
                event_id=str(uuid.uuid4()),
                threat_type=ThreatType.SESSION_HIJACKING,
                severity=severity,
                confidence=confidence,
                user_id=user_profile.get('user_id', 'unknown'),
                session_id=session_id,
                description=f"Session hijacking indicators detected: {', '.join([a['type'] for a in anomalies])}",
                attack_stage=AttackStage.LATERAL_MOVEMENT,
                attack_vectors=[AttackVector(
                    vector_id=str(uuid.uuid4()),
                    attack_type=ThreatType.SESSION_HIJACKING,
                    confidence=anomaly['severity'],
                    description=anomaly['description'],
                    evidence=anomaly['details']
                ) for anomaly in anomalies],
                recommendations=[
                    "Immediately terminate suspicious session",
                    "Force user re-authentication",
                    "Review session tokens and cookies",
                    "Audit network security controls",
                    "Implement session binding to IP/device",
                    "Monitor for continued unauthorized access"
                ],
                raw_evidence={'session_anomalies': anomalies}
            )
        
        return None
    
    async def _detect_concurrent_session_abuse(self, session_id: str, events: List[Dict[str, Any]], 
                                             user_profile: Dict[str, Any]) -> Optional[ThreatEvent]:
        """Detect abuse of concurrent sessions"""
        # Check if user has too many concurrent sessions
        concurrent_sessions = user_profile.get('concurrent_sessions', 1)
        max_allowed = user_profile.get('max_concurrent_sessions', 3)
        
        if concurrent_sessions > max_allowed and concurrent_sessions > 5:
            # Check for suspicious patterns in concurrent access
            session_ips = list(set(e.get('source_ip') for e in events if e.get('source_ip')))
            
            if len(session_ips) > 1:
                confidence = min(0.9, concurrent_sessions * 0.1)
                
                return ThreatEvent(
                    event_id=str(uuid.uuid4()),
                    threat_type=ThreatType.ACCOUNT_TAKEOVER,
                    severity=ThreatSeverity.HIGH,
                    confidence=confidence,
                    user_id=user_profile.get('user_id', 'unknown'),
                    session_id=session_id,
                    description=f"Suspicious concurrent session activity: {concurrent_sessions} active sessions from {len(session_ips)} IP addresses",
                    attack_stage=AttackStage.PERSISTENCE,
                    attack_vectors=[AttackVector(
                        vector_id=str(uuid.uuid4()),
                        attack_type=ThreatType.ACCOUNT_TAKEOVER,
                        source_ip=ip,
                        confidence=confidence,
                        description=f"Concurrent session from IP {ip}",
                        evidence={'session_id': session_id}
                    ) for ip in session_ips],
                    recommendations=[
                        "Review all active sessions for the user",
                        "Terminate suspicious sessions",
                        "Implement session limits per user",
                        "Monitor for shared credential usage",
                        "Audit access patterns across sessions"
                    ],
                    raw_evidence={
                        'concurrent_sessions': concurrent_sessions,
                        'session_ips': session_ips,
                        'max_allowed': max_allowed
                    }
                )
        
        return None
    
    async def _detect_behavior_pattern_change(self, events: List[Dict[str, Any]], 
                                            user_profile: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Detect significant behavior pattern changes within session"""
        # Analyze action patterns
        actions = [e.get('action') for e in events if e.get('action')]
        normal_actions = user_profile.get('normal_actions', [])
        
        if actions and normal_actions:
            unusual_actions = [a for a in actions if a not in normal_actions]
            if len(unusual_actions) / len(actions) > 0.5:  # More than 50% unusual actions
                return {
                    'type': 'behavior_pattern_change',
                    'severity': 0.7,
                    'description': f"Significant behavior change: {len(unusual_actions)} unusual actions out of {len(actions)}",
                    'details': {
                        'unusual_actions': unusual_actions,
                        'normal_actions': normal_actions,
                        'unusual_ratio': len(unusual_actions) / len(actions)
                    }
                }
        
        return None
    
    def _extract_location(self, event: Dict[str, Any]) -> Optional[Dict[str, float]]:
        """Extract location information from event"""
        lat = event.get('latitude') or event.get('geo_location', {}).get('latitude')
        lon = event.get('longitude') or event.get('geo_location', {}).get('longitude')
        
        if lat is not None and lon is not None:
            return {'lat': float(lat), 'lon': float(lon)}
        
        return None
    
    def _haversine_distance(self, lat1: float, lon1: float, lat2: float, lon2: float) -> float:
        """Calculate haversine distance between two points"""
        R = 6371  # Earth's radius in kilometers
        
        lat1_rad = math.radians(lat1)
        lon1_rad = math.radians(lon1)
        lat2_rad = math.radians(lat2)
        lon2_rad = math.radians(lon2)
        
        dlat = lat2_rad - lat1_rad
        dlon = lon2_rad - lon1_rad
        
        a = math.sin(dlat/2)**2 + math.cos(lat1_rad) * math.cos(lat2_rad) * math.sin(dlon/2)**2
        c = 2 * math.asin(math.sqrt(a))
        
        return R * c


class APTDetector:
    """Advanced Persistent Threat detector"""
    
    def __init__(self, redis_client: Optional[redis.Redis] = None):
        self.redis_client = redis_client
        self.apt_indicators = {
            'living_off_land': ['powershell', 'wmic', 'rundll32', 'regsvr32', 'mshta'],
            'persistence_locations': ['/startup/', '/autostart/', '/scheduled/', '/service/'],
            'lateral_movement_tools': ['psexec', 'wmiexec', 'smbexec', 'rdp', 'ssh'],
            'data_collection': ['dir', 'ls', 'find', 'locate', 'search'],
            'exfiltration_protocols': ['ftp', 'http', 'dns', 'smtp', 'cloud']
        }
    
    async def detect_apt_behavior(self, events: List[Dict[str, Any]], 
                                user_profile: Dict[str, Any], 
                                time_window_days: int = 30) -> List[ThreatEvent]:
        """Detect APT-style behavior patterns"""
        threats = []
        
        # Filter events to time window
        cutoff_time = datetime.now(timezone.utc) - timedelta(days=time_window_days)
        recent_events = [
            e for e in events 
            if datetime.fromisoformat(e['timestamp'].replace('Z', '+00:00')) >= cutoff_time
        ]
        
        # Detect long-term persistence
        persistence_threat = await self._detect_persistence_mechanisms(recent_events, user_profile)
        if persistence_threat:
            threats.append(persistence_threat)
        
        # Detect lateral movement patterns
        lateral_threat = await self._detect_lateral_movement(recent_events, user_profile)
        if lateral_threat:
            threats.append(lateral_threat)
        
        # Detect data collection and staging
        collection_threat = await self._detect_data_collection(recent_events, user_profile)
        if collection_threat:
            threats.append(collection_threat)
        
        # Detect living-off-the-land techniques
        lotl_threat = await self._detect_living_off_land(recent_events, user_profile)
        if lotl_threat:
            threats.append(lotl_threat)
        
        return threats
    
    async def _detect_persistence_mechanisms(self, events: List[Dict[str, Any]], 
                                          user_profile: Dict[str, Any]) -> Optional[ThreatEvent]:
        """Detect persistence establishment"""
        persistence_indicators = []
        
        for event in events:
            action = event.get('action', '').lower()
            resource = event.get('resource', '').lower()
            
            # Check for persistence-related activities
            for location in self.apt_indicators['persistence_locations']:
                if location in action or location in resource:
                    persistence_indicators.append({
                        'type': 'persistence_location',
                        'location': location,
                        'action': action,
                        'resource': resource,
                        'timestamp': event.get('timestamp')
                    })
            
            # Check for scheduled task creation
            if 'schedule' in action or 'cron' in action or 'task' in action:
                if 'create' in action or 'add' in action:
                    persistence_indicators.append({
                        'type': 'scheduled_task',
                        'action': action,
                        'resource': resource,
                        'timestamp': event.get('timestamp')
                    })
            
            # Check for service modifications
            if 'service' in action or 'daemon' in action:
                if any(verb in action for verb in ['create', 'modify', 'install', 'start']):
                    persistence_indicators.append({
                        'type': 'service_modification',
                        'action': action,
                        'resource': resource,
                        'timestamp': event.get('timestamp')
                    })
        
        if persistence_indicators:
            confidence = min(0.9, len(persistence_indicators) * 0.3)
            
            return ThreatEvent(
                event_id=str(uuid.uuid4()),
                threat_type=ThreatType.APT_BEHAVIOR,
                severity=ThreatSeverity.HIGH,
                confidence=confidence,
                user_id=user_profile.get('user_id', 'unknown'),
                description=f"APT persistence mechanisms detected: {len(persistence_indicators)} indicators",
                attack_stage=AttackStage.PERSISTENCE,
                attack_vectors=[AttackVector(
                    vector_id=str(uuid.uuid4()),
                    attack_type=ThreatType.APT_BEHAVIOR,
                    confidence=confidence * 0.8,
                    description=f"Persistence mechanism: {indicator['type']}",
                    evidence=indicator
                ) for indicator in persistence_indicators],
                recommendations=[
                    "Audit all persistence mechanisms (scheduled tasks, services, startup items)",
                    "Review recent system modifications",
                    "Implement application whitelisting",
                    "Monitor for unauthorized system changes",
                    "Conduct full system forensics"
                ],
                raw_evidence={'persistence_indicators': persistence_indicators}
            )
        
        return None
    
    async def _detect_lateral_movement(self, events: List[Dict[str, Any]], 
                                     user_profile: Dict[str, Any]) -> Optional[ThreatEvent]:
        """Detect lateral movement patterns"""
        lateral_indicators = []
        
        # Track resource access patterns
        accessed_resources = defaultdict(list)
        for event in events:
            resource = event.get('resource')
            if resource:
                accessed_resources[resource].append(event)
        
        # Look for expansion of access
        baseline_resources = set(user_profile.get('normal_resources', []))
        new_resources = [r for r in accessed_resources.keys() if r not in baseline_resources]
        
        if len(new_resources) > 5:  # Accessing many new resources
            lateral_indicators.append({
                'type': 'resource_expansion',
                'new_resources_count': len(new_resources),
                'new_resources': new_resources[:10]  # Limit for storage
            })
        
        # Check for lateral movement tools usage
        for event in events:
            action = event.get('action', '').lower()
            resource = event.get('resource', '').lower()
            
            for tool in self.apt_indicators['lateral_movement_tools']:
                if tool in action or tool in resource:
                    lateral_indicators.append({
                        'type': 'lateral_movement_tool',
                        'tool': tool,
                        'action': action,
                        'resource': resource,
                        'timestamp': event.get('timestamp')
                    })
        
        # Check for privilege escalation attempts
        for event in events:
            action = event.get('action', '').lower()
            if any(term in action for term in ['sudo', 'runas', 'elevate', 'admin']):
                lateral_indicators.append({
                    'type': 'privilege_escalation',
                    'action': action,
                    'timestamp': event.get('timestamp')
                })
        
        if lateral_indicators:
            confidence = min(0.85, len(lateral_indicators) * 0.25)
            
            return ThreatEvent(
                event_id=str(uuid.uuid4()),
                threat_type=ThreatType.LATERAL_MOVEMENT,
                severity=ThreatSeverity.HIGH,
                confidence=confidence,
                user_id=user_profile.get('user_id', 'unknown'),
                description=f"Lateral movement patterns detected: {len(lateral_indicators)} indicators",
                attack_stage=AttackStage.LATERAL_MOVEMENT,
                attack_vectors=[AttackVector(
                    vector_id=str(uuid.uuid4()),
                    attack_type=ThreatType.LATERAL_MOVEMENT,
                    confidence=confidence * 0.8,
                    description=f"Lateral movement indicator: {indicator['type']}",
                    evidence=indicator
                ) for indicator in lateral_indicators],
                recommendations=[
                    "Implement network segmentation",
                    "Monitor for unauthorized privilege escalation",
                    "Audit lateral movement tools usage",
                    "Review access patterns across systems",
                    "Implement just-in-time access controls"
                ],
                raw_evidence={'lateral_indicators': lateral_indicators}
            )
        
        return None
    
    async def _detect_data_collection(self, events: List[Dict[str, Any]], 
                                    user_profile: Dict[str, Any]) -> Optional[ThreatEvent]:
        """Detect data collection and staging activities"""
        collection_indicators = []
        
        for event in events:
            action = event.get('action', '').lower()
            resource = event.get('resource', '').lower()
            
            # Check for data collection commands
            for tool in self.apt_indicators['data_collection']:
                if tool in action:
                    collection_indicators.append({
                        'type': 'data_collection_tool',
                        'tool': tool,
                        'action': action,
                        'resource': resource,
                        'timestamp': event.get('timestamp')
                    })
            
            # Check for large data access
            if any(term in action for term in ['download', 'copy', 'export', 'backup']):
                # Estimate data size if available
                size = event.get('data_size') or event.get('file_size')
                if size and size > 1000000:  # > 1MB
                    collection_indicators.append({
                        'type': 'large_data_access',
                        'action': action,
                        'resource': resource,
                        'size': size,
                        'timestamp': event.get('timestamp')
                    })
            
            # Check for sensitive data access
            sensitive_patterns = ['password', 'secret', 'key', 'token', 'credential', 'config']
            if any(pattern in resource for pattern in sensitive_patterns):
                collection_indicators.append({
                    'type': 'sensitive_data_access',
                    'resource': resource,
                    'action': action,
                    'timestamp': event.get('timestamp')
                })
        
        if collection_indicators:
            confidence = min(0.8, len(collection_indicators) * 0.3)
            
            return ThreatEvent(
                event_id=str(uuid.uuid4()),
                threat_type=ThreatType.APT_BEHAVIOR,
                severity=ThreatSeverity.MEDIUM,
                confidence=confidence,
                user_id=user_profile.get('user_id', 'unknown'),
                description=f"Data collection activities detected: {len(collection_indicators)} indicators",
                attack_stage=AttackStage.COLLECTION,
                attack_vectors=[AttackVector(
                    vector_id=str(uuid.uuid4()),
                    attack_type=ThreatType.APT_BEHAVIOR,
                    confidence=confidence * 0.8,
                    description=f"Data collection: {indicator['type']}",
                    evidence=indicator
                ) for indicator in collection_indicators],
                recommendations=[
                    "Monitor data access patterns",
                    "Implement data loss prevention (DLP)",
                    "Audit sensitive data access",
                    "Review data classification and protection",
                    "Monitor for unusual data transfers"
                ],
                raw_evidence={'collection_indicators': collection_indicators}
            )
        
        return None
    
    async def _detect_living_off_land(self, events: List[Dict[str, Any]], 
                                    user_profile: Dict[str, Any]) -> Optional[ThreatEvent]:
        """Detect living-off-the-land techniques"""
        lotl_indicators = []
        
        for event in events:
            action = event.get('action', '').lower()
            resource = event.get('resource', '').lower()
            command = event.get('command', '').lower()
            
            # Check for living-off-the-land tools
            for tool in self.apt_indicators['living_off_land']:
                if tool in action or tool in command:
                    lotl_indicators.append({
                        'type': 'living_off_land_tool',
                        'tool': tool,
                        'action': action,
                        'command': command,
                        'timestamp': event.get('timestamp')
                    })
            
            # Check for suspicious PowerShell usage
            if 'powershell' in action or 'powershell' in command:
                suspicious_patterns = ['downloadstring', 'invoke-expression', 'bypass', 'hidden', 'encoded']
                if any(pattern in command for pattern in suspicious_patterns):
                    lotl_indicators.append({
                        'type': 'suspicious_powershell',
                        'command': command,
                        'action': action,
                        'timestamp': event.get('timestamp')
                    })
        
        if lotl_indicators:
            confidence = min(0.85, len(lotl_indicators) * 0.4)
            
            return ThreatEvent(
                event_id=str(uuid.uuid4()),
                threat_type=ThreatType.APT_BEHAVIOR,
                severity=ThreatSeverity.HIGH,
                confidence=confidence,
                user_id=user_profile.get('user_id', 'unknown'),
                description=f"Living-off-the-land techniques detected: {len(lotl_indicators)} indicators",
                attack_stage=AttackStage.DEFENSE_EVASION,
                attack_vectors=[AttackVector(
                    vector_id=str(uuid.uuid4()),
                    attack_type=ThreatType.APT_BEHAVIOR,
                    confidence=confidence * 0.8,
                    description=f"LotL technique: {indicator['type']}",
                    evidence=indicator
                ) for indicator in lotl_indicators],
                recommendations=[
                    "Implement application whitelisting",
                    "Monitor PowerShell execution and logging",
                    "Restrict administrative tools usage",
                    "Deploy behavioral monitoring",
                    "Review system administration policies"
                ],
                raw_evidence={'lotl_indicators': lotl_indicators}
            )
        
        return None


class ThreatIntelligenceManager:
    """Threat intelligence integration and management"""
    
    def __init__(self, db_path: str = "threat_intelligence.db"):
        self.db_path = db_path
        self.indicators = {}  # In-memory cache
        self.feed_configs = {}
        self.initialized = False
    
    async def initialize(self):
        """Initialize threat intelligence database"""
        if self.initialized:
            return
        
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                CREATE TABLE IF NOT EXISTS threat_indicators (
                    indicator_id TEXT PRIMARY KEY,
                    indicator_type TEXT NOT NULL,
                    indicator_value TEXT NOT NULL,
                    threat_types TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    severity TEXT NOT NULL,
                    source TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    description TEXT,
                    tags TEXT,
                    ttl_hours INTEGER DEFAULT 24,
                    active BOOLEAN DEFAULT 1,
                    metadata TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            await db.execute("""
                CREATE INDEX IF NOT EXISTS idx_indicators_value ON threat_indicators(indicator_value)
            """)
            
            await db.execute("""
                CREATE INDEX IF NOT EXISTS idx_indicators_type ON threat_indicators(indicator_type)
            """)
            
            await db.commit()
        
        await self._load_indicators()
        self.initialized = True
        logging.info("Threat Intelligence Manager initialized")
    
    async def add_indicator(self, indicator: ThreatIndicator) -> bool:
        """Add threat indicator"""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute("""
                    INSERT OR REPLACE INTO threat_indicators (
                        indicator_id, indicator_type, indicator_value, threat_types,
                        confidence, severity, source, first_seen, last_seen, description,
                        tags, ttl_hours, active, metadata, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    indicator.indicator_id, indicator.indicator_type, indicator.indicator_value,
                    json.dumps([tt.value for tt in indicator.threat_types]),
                    indicator.confidence, indicator.severity.value, indicator.source.value,
                    indicator.first_seen.isoformat(), indicator.last_seen.isoformat(),
                    indicator.description, json.dumps(indicator.tags), indicator.ttl_hours,
                    indicator.active, json.dumps(indicator.metadata) if indicator.metadata else None,
                    datetime.now(timezone.utc).isoformat()
                ))
                await db.commit()
            
            # Update cache
            self.indicators[indicator.indicator_value] = indicator
            
            return True
            
        except Exception as e:
            logging.error(f"Failed to add threat indicator: {e}")
            return False
    
    async def check_indicators(self, values: List[str]) -> Dict[str, ThreatIndicator]:
        """Check values against threat indicators"""
        matches = {}
        
        for value in values:
            if value in self.indicators:
                indicator = self.indicators[value]
                
                # Check if indicator is still valid (not expired)
                if indicator.active:
                    expiry_time = indicator.last_seen + timedelta(hours=indicator.ttl_hours)
                    if datetime.now(timezone.utc) <= expiry_time:
                        matches[value] = indicator
        
        return matches
    
    async def update_indicators_from_feed(self, feed_url: str, feed_type: str = "json") -> int:
        """Update indicators from external threat feed"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(feed_url) as response:
                    if response.status == 200:
                        if feed_type == "json":
                            data = await response.json()
                            return await self._process_json_feed(data)
                        elif feed_type == "csv":
                            text = await response.text()
                            return await self._process_csv_feed(text)
                    else:
                        logging.error(f"Failed to fetch threat feed: {response.status}")
                        return 0
                        
        except Exception as e:
            logging.error(f"Error updating from threat feed: {e}")
            return 0
    
    async def _load_indicators(self):
        """Load indicators from database into memory"""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                async with db.execute("SELECT * FROM threat_indicators WHERE active = 1") as cursor:
                    rows = await cursor.fetchall()
                    columns = [description[0] for description in cursor.description]
                    
                    for row in rows:
                        row_dict = dict(zip(columns, row))
                        
                        indicator = ThreatIndicator(
                            indicator_id=row_dict['indicator_id'],
                            indicator_type=row_dict['indicator_type'],
                            indicator_value=row_dict['indicator_value'],
                            threat_types=[ThreatType(tt) for tt in json.loads(row_dict['threat_types'])],
                            confidence=row_dict['confidence'],
                            severity=ThreatSeverity(row_dict['severity']),
                            source=ThreatIntelligenceSource(row_dict['source']),
                            first_seen=datetime.fromisoformat(row_dict['first_seen']),
                            last_seen=datetime.fromisoformat(row_dict['last_seen']),
                            description=row_dict['description'] or '',
                            tags=json.loads(row_dict['tags']) if row_dict['tags'] else [],
                            ttl_hours=row_dict['ttl_hours'],
                            active=bool(row_dict['active']),
                            metadata=json.loads(row_dict['metadata']) if row_dict['metadata'] else None
                        )
                        
                        self.indicators[indicator.indicator_value] = indicator
            
            logging.info(f"Loaded {len(self.indicators)} threat indicators")
            
        except Exception as e:
            logging.error(f"Failed to load threat indicators: {e}")
    
    async def _process_json_feed(self, data: Dict[str, Any]) -> int:
        """Process JSON threat intelligence feed"""
        count = 0
        
        # This is a simplified example - real feeds would have different formats
        indicators_data = data.get('indicators', [])
        
        for item in indicators_data:
            try:
                threat_types = [ThreatType(tt) for tt in item.get('threat_types', [])]
                
                indicator = ThreatIndicator(
                    indicator_id=item.get('id') or str(uuid.uuid4()),
                    indicator_type=item.get('type', 'unknown'),
                    indicator_value=item.get('value', ''),
                    threat_types=threat_types,
                    confidence=item.get('confidence', 0.5),
                    severity=ThreatSeverity(item.get('severity', 'medium')),
                    source=ThreatIntelligenceSource.COMMERCIAL_FEED,
                    first_seen=datetime.now(timezone.utc),
                    last_seen=datetime.now(timezone.utc),
                    description=item.get('description', ''),
                    tags=item.get('tags', []),
                    ttl_hours=item.get('ttl_hours', 24)
                )
                
                if await self.add_indicator(indicator):
                    count += 1
                    
            except Exception as e:
                logging.warning(f"Failed to process indicator: {e}")
                continue
        
        return count
    
    async def _process_csv_feed(self, csv_data: str) -> int:
        """Process CSV threat intelligence feed"""
        count = 0
        lines = csv_data.strip().split('\n')
        
        if len(lines) < 2:
            return 0
        
        # Assume first line is header
        headers = [h.strip() for h in lines[0].split(',')]
        
        for line in lines[1:]:
            try:
                values = [v.strip() for v in line.split(',')]
                row_dict = dict(zip(headers, values))
                
                indicator = ThreatIndicator(
                    indicator_id=str(uuid.uuid4()),
                    indicator_type=row_dict.get('type', 'ip'),
                    indicator_value=row_dict.get('value', ''),
                    threat_types=[ThreatType.CREDENTIAL_THEFT],  # Default
                    confidence=float(row_dict.get('confidence', 0.5)),
                    severity=ThreatSeverity(row_dict.get('severity', 'medium')),
                    source=ThreatIntelligenceSource.COMMERCIAL_FEED,
                    first_seen=datetime.now(timezone.utc),
                    last_seen=datetime.now(timezone.utc),
                    description=row_dict.get('description', ''),
                    tags=[],
                    ttl_hours=int(row_dict.get('ttl_hours', 24))
                )
                
                if await self.add_indicator(indicator):
                    count += 1
                    
            except Exception as e:
                logging.warning(f"Failed to process CSV row: {e}")
                continue
        
        return count


class IdentityThreatDetectionEngine:
    """Main identity threat detection engine"""
    
    def __init__(self, db_path: str = "identity_threats.db", redis_url: str = "redis://localhost:6379"):
        self.db_path = db_path
        self.redis_url = redis_url
        self.redis_client = None
        
        # Initialize detectors
        self.credential_detector = CredentialTheftDetector()
        self.brute_force_detector = BruteForceDetector()
        self.session_detector = SessionHijackingDetector()
        self.apt_detector = APTDetector()
        self.threat_intel = ThreatIntelligenceManager()
        
        # Statistics
        self.stats = {
            'threats_detected': 0,
            'false_positives': 0,
            'campaigns_identified': 0,
            'indicators_processed': 0,
            'start_time': datetime.now(timezone.utc)
        }
        
        self.initialized = False
        logging.info("Identity Threat Detection Engine initialized")
    
    async def initialize(self):
        """Initialize the threat detection engine"""
        if self.initialized:
            return
        
        # Initialize database
        await self._initialize_database()
        
        # Initialize Redis
        try:
            self.redis_client = redis.from_url(self.redis_url)
            await self.redis_client.ping()
            
            # Update detector Redis clients
            self.credential_detector.redis_client = self.redis_client
            self.brute_force_detector.redis_client = self.redis_client
            self.session_detector.redis_client = self.redis_client
            self.apt_detector.redis_client = self.redis_client
            
            logging.info("Redis connection established")
        except Exception as e:
            logging.warning(f"Redis connection failed: {e}")
        
        # Initialize threat intelligence
        await self.threat_intel.initialize()
        
        self.initialized = True
        logging.info("Identity Threat Detection Engine fully initialized")
    
    async def detect_threats(self, events: List[Dict[str, Any]], 
                           user_profiles: Dict[str, Dict[str, Any]]) -> List[ThreatEvent]:
        """Main threat detection method"""
        if not self.initialized:
            await self.initialize()
        
        all_threats = []
        
        # Group events by user
        user_events = defaultdict(list)
        for event in events:
            user_id = event.get('user_id')
            if user_id:
                user_events[user_id].append(event)
        
        # Process each user's events
        for user_id, user_event_list in user_events.items():
            user_profile = user_profiles.get(user_id, {})
            
            try:
                # Credential theft detection
                credential_threats = await self.credential_detector.detect_credential_theft(
                    user_event_list, user_profile
                )
                all_threats.extend(credential_threats)
                
                # Session hijacking detection
                session_threats = await self.session_detector.detect_session_hijacking(
                    user_event_list, user_profile
                )
                all_threats.extend(session_threats)
                
                # APT behavior detection
                apt_threats = await self.apt_detector.detect_apt_behavior(
                    user_event_list, user_profile
                )
                all_threats.extend(apt_threats)
                
            except Exception as e:
                logging.error(f"Error detecting threats for user {user_id}: {e}")
        
        # Brute force detection (across all events)
        try:
            brute_force_threats = await self.brute_force_detector.detect_brute_force(events)
            all_threats.extend(brute_force_threats)
        except Exception as e:
            logging.error(f"Error detecting brute force attacks: {e}")
        
        # Enrich threats with threat intelligence
        for threat in all_threats:
            await self._enrich_with_threat_intel(threat)
        
        # Store detected threats
        for threat in all_threats:
            await self._store_threat_event(threat)
        
        # Update statistics
        self.stats['threats_detected'] += len(all_threats)
        
        # Correlate threats and identify campaigns
        campaigns = await self._correlate_threats(all_threats)
        self.stats['campaigns_identified'] += len(campaigns)
        
        logging.info(f"Detected {len(all_threats)} threats across {len(campaigns)} campaigns")
        
        return all_threats
    
    async def _enrich_with_threat_intel(self, threat: ThreatEvent):
        """Enrich threat with intelligence data"""
        try:
            # Collect IOCs from threat
            iocs = []
            
            if threat.source_ip:
                iocs.append(threat.source_ip)
            
            for vector in threat.attack_vectors:
                if vector.source_ip:
                    iocs.append(vector.source_ip)
            
            # Check against threat intelligence
            matches = await self.threat_intel.check_indicators(iocs)
            
            if matches:
                threat.indicators = list(matches.keys())
                
                # Update confidence based on threat intel matches
                intel_confidence = max(match.confidence for match in matches.values())
                threat.confidence = min(0.98, threat.confidence + (intel_confidence * 0.2))
                
                # Update severity if threat intel indicates higher severity
                intel_severities = [match.severity for match in matches.values()]
                if ThreatSeverity.CRITICAL in intel_severities and threat.severity != ThreatSeverity.CRITICAL:
                    threat.severity = ThreatSeverity.CRITICAL
                elif ThreatSeverity.HIGH in intel_severities and threat.severity not in [ThreatSeverity.CRITICAL, ThreatSeverity.HIGH]:
                    threat.severity = ThreatSeverity.HIGH
                
                # Add intelligence-based recommendations
                for ioc, indicator in matches.items():
                    threat.recommendations.append(f"IOC {ioc} matches known threat: {indicator.description}")
        
        except Exception as e:
            logging.error(f"Failed to enrich threat with intelligence: {e}")
    
    async def _correlate_threats(self, threats: List[ThreatEvent]) -> List[ThreatCampaign]:
        """Correlate threats into campaigns"""
        if not threats:
            return []
        
        campaigns = []
        
        # Group threats by various criteria
        ip_groups = defaultdict(list)
        user_groups = defaultdict(list)
        time_groups = defaultdict(list)
        
        for threat in threats:
            # Group by source IP
            if threat.source_ip:
                ip_groups[threat.source_ip].append(threat)
            
            # Group by user
            user_groups[threat.user_id].append(threat)
            
            # Group by time window (1 hour windows)
            time_bucket = threat.timestamp.replace(minute=0, second=0, microsecond=0)
            time_groups[time_bucket].append(threat)
        
        # Create campaigns for correlated threats
        processed_threats = set()
        
        # IP-based correlation
        for ip, ip_threats in ip_groups.items():
            if len(ip_threats) >= 3 and not all(t.event_id in processed_threats for t in ip_threats):
                campaign = await self._create_campaign(ip_threats, f"IP-based campaign from {ip}")
                campaigns.append(campaign)
                
                for threat in ip_threats:
                    processed_threats.add(threat.event_id)
                    threat.campaign_id = campaign.campaign_id
        
        # Multi-user correlation (same time, different users - potential coordinated attack)
        for time_bucket, time_threats in time_groups.items():
            users = set(t.user_id for t in time_threats)
            if len(users) >= 3 and len(time_threats) >= 5:
                unprocessed_threats = [t for t in time_threats if t.event_id not in processed_threats]
                if len(unprocessed_threats) >= 3:
                    campaign = await self._create_campaign(
                        unprocessed_threats, 
                        f"Coordinated attack campaign at {time_bucket.isoformat()}"
                    )
                    campaigns.append(campaign)
                    
                    for threat in unprocessed_threats:
                        processed_threats.add(threat.event_id)
                        threat.campaign_id = campaign.campaign_id
        
        return campaigns
    
    async def _create_campaign(self, threats: List[ThreatEvent], name: str) -> ThreatCampaign:
        """Create threat campaign from correlated threats"""
        campaign_id = str(uuid.uuid4())
        
        # Aggregate threat information
        threat_types = list(set(t.threat_type for t in threats))
        affected_users = set(t.user_id for t in threats)
        source_ips = set(t.source_ip for t in threats if t.source_ip)
        attack_stages = list(set(t.attack_stage for t in threats if t.attack_stage))
        
        # Calculate overall severity and confidence
        severities = [t.severity for t in threats]
        confidences = [t.confidence for t in threats]
        
        max_severity = max(severities, key=lambda x: ['info', 'low', 'medium', 'high', 'critical'].index(x.value))
        avg_confidence = sum(confidences) / len(confidences)
        
        # Determine time range
        timestamps = [t.timestamp for t in threats]
        start_time = min(timestamps)
        end_time = max(timestamps)
        
        campaign = ThreatCampaign(
            campaign_id=campaign_id,
            campaign_name=name,
            threat_types=threat_types,
            severity=max_severity,
            confidence=avg_confidence,
            start_time=start_time,
            end_time=end_time,
            threat_events=[t.event_id for t in threats],
            affected_users=affected_users,
            source_ips=source_ips,
            tactics=attack_stages,
            description=f"Campaign involving {len(threat_types)} threat types across {len(affected_users)} users",
            attack_pattern=self._analyze_attack_pattern(threats)
        )
        
        # Store campaign
        await self._store_campaign(campaign)
        
        return campaign
    
    def _analyze_attack_pattern(self, threats: List[ThreatEvent]) -> str:
        """Analyze attack pattern from threats"""
        patterns = []
        
        # Analyze threat type distribution
        threat_counts = defaultdict(int)
        for threat in threats:
            threat_counts[threat.threat_type] += 1
        
        if threat_counts[ThreatType.BRUTE_FORCE] > 0 and threat_counts[ThreatType.CREDENTIAL_THEFT] > 0:
            patterns.append("credential_attack_sequence")
        
        if threat_counts[ThreatType.LATERAL_MOVEMENT] > 0 and threat_counts[ThreatType.PRIVILEGE_ESCALATION] > 0:
            patterns.append("privilege_escalation_campaign")
        
        if len(set(t.user_id for t in threats)) > 5:
            patterns.append("multi_user_targeting")
        
        if len(set(t.source_ip for t in threats if t.source_ip)) > 3:
            patterns.append("distributed_attack")
        
        return ", ".join(patterns) if patterns else "unknown_pattern"
    
    async def _initialize_database(self):
        """Initialize threat detection database"""
        async with aiosqlite.connect(self.db_path) as db:
            # Threat events table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS threat_events (
                    event_id TEXT PRIMARY KEY,
                    threat_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    user_id TEXT NOT NULL,
                    source_ip TEXT,
                    user_agent TEXT,
                    session_id TEXT,
                    application TEXT,
                    resource TEXT,
                    attack_stage TEXT,
                    description TEXT,
                    recommendations TEXT,
                    raw_evidence TEXT,
                    indicators TEXT,
                    campaign_id TEXT,
                    timestamp TEXT NOT NULL,
                    ttl_hours INTEGER DEFAULT 168,
                    status TEXT DEFAULT 'active',
                    false_positive BOOLEAN DEFAULT 0,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Threat campaigns table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS threat_campaigns (
                    campaign_id TEXT PRIMARY KEY,
                    campaign_name TEXT NOT NULL,
                    threat_types TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    start_time TEXT NOT NULL,
                    end_time TEXT,
                    threat_events TEXT,
                    affected_users TEXT,
                    source_ips TEXT,
                    attack_pattern TEXT,
                    threat_actor TEXT,
                    attribution_confidence REAL DEFAULT 0.0,
                    tactics TEXT,
                    description TEXT,
                    status TEXT DEFAULT 'active',
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Create indexes
            indexes = [
                "CREATE INDEX IF NOT EXISTS idx_threats_user ON threat_events(user_id)",
                "CREATE INDEX IF NOT EXISTS idx_threats_timestamp ON threat_events(timestamp)",
                "CREATE INDEX IF NOT EXISTS idx_threats_type ON threat_events(threat_type)",
                "CREATE INDEX IF NOT EXISTS idx_threats_severity ON threat_events(severity)",
                "CREATE INDEX IF NOT EXISTS idx_threats_campaign ON threat_events(campaign_id)",
                "CREATE INDEX IF NOT EXISTS idx_campaigns_start_time ON threat_campaigns(start_time)"
            ]
            
            for index_sql in indexes:
                await db.execute(index_sql)
            
            await db.commit()
        
        logging.info("Identity Threat Detection database initialized")
    
    async def _store_threat_event(self, threat: ThreatEvent):
        """Store threat event in database"""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute("""
                    INSERT OR REPLACE INTO threat_events (
                        event_id, threat_type, severity, confidence, user_id,
                        source_ip, user_agent, session_id, application, resource,
                        attack_stage, description, recommendations, raw_evidence,
                        indicators, campaign_id, timestamp, ttl_hours, status,
                        false_positive
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    threat.event_id, threat.threat_type.value, threat.severity.value,
                    threat.confidence, threat.user_id, threat.source_ip, threat.user_agent,
                    threat.session_id, threat.application, threat.resource,
                    threat.attack_stage.value if threat.attack_stage else None,
                    threat.description, json.dumps(threat.recommendations),
                    json.dumps(threat.raw_evidence), json.dumps(threat.indicators),
                    threat.campaign_id, threat.timestamp.isoformat(), threat.ttl_hours,
                    threat.status, threat.false_positive
                ))
                await db.commit()
        except Exception as e:
            logging.error(f"Failed to store threat event: {e}")
    
    async def _store_campaign(self, campaign: ThreatCampaign):
        """Store threat campaign in database"""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute("""
                    INSERT OR REPLACE INTO threat_campaigns (
                        campaign_id, campaign_name, threat_types, severity, confidence,
                        start_time, end_time, threat_events, affected_users, source_ips,
                        attack_pattern, threat_actor, attribution_confidence, tactics,
                        description, status, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    campaign.campaign_id, campaign.campaign_name,
                    json.dumps([tt.value for tt in campaign.threat_types]),
                    campaign.severity.value, campaign.confidence,
                    campaign.start_time.isoformat(),
                    campaign.end_time.isoformat() if campaign.end_time else None,
                    json.dumps(campaign.threat_events), json.dumps(list(campaign.affected_users)),
                    json.dumps(list(campaign.source_ips)), campaign.attack_pattern,
                    campaign.threat_actor, campaign.attribution_confidence,
                    json.dumps([t.value for t in campaign.tactics]) if campaign.tactics else None,
                    campaign.description, campaign.status,
                    datetime.now(timezone.utc).isoformat()
                ))
                await db.commit()
        except Exception as e:
            logging.error(f"Failed to store threat campaign: {e}")
    
    async def get_threat_summary(self, days: int = 7) -> Dict[str, Any]:
        """Get threat detection summary"""
        cutoff_time = datetime.now(timezone.utc) - timedelta(days=days)
        
        summary = {
            'time_period_days': days,
            'total_threats': 0,
            'threats_by_type': {},
            'threats_by_severity': {},
            'active_campaigns': 0,
            'affected_users': set(),
            'threat_sources': set(),
            'recommendations': []
        }
        
        try:
            async with aiosqlite.connect(self.db_path) as db:
                # Get threat counts
                async with db.execute("""
                    SELECT threat_type, severity, user_id, source_ip
                    FROM threat_events 
                    WHERE timestamp >= ? AND status = 'active'
                """, (cutoff_time.isoformat(),)) as cursor:
                    
                    rows = await cursor.fetchall()
                    summary['total_threats'] = len(rows)
                    
                    for row in rows:
                        threat_type, severity, user_id, source_ip = row
                        
                        # Count by type
                        summary['threats_by_type'][threat_type] = summary['threats_by_type'].get(threat_type, 0) + 1
                        
                        # Count by severity
                        summary['threats_by_severity'][severity] = summary['threats_by_severity'].get(severity, 0) + 1
                        
                        # Track affected entities
                        if user_id:
                            summary['affected_users'].add(user_id)
                        if source_ip:
                            summary['threat_sources'].add(source_ip)
                
                # Get active campaigns
                async with db.execute("""
                    SELECT COUNT(*) FROM threat_campaigns 
                    WHERE start_time >= ? AND status = 'active'
                """, (cutoff_time.isoformat(),)) as cursor:
                    row = await cursor.fetchone()
                    summary['active_campaigns'] = row[0] if row else 0
        
        except Exception as e:
            logging.error(f"Failed to get threat summary: {e}")
        
        # Convert sets to counts
        summary['affected_users'] = len(summary['affected_users'])
        summary['threat_sources'] = len(summary['threat_sources'])
        
        # Generate recommendations
        if summary['total_threats'] > 0:
            if summary['threats_by_type'].get('brute_force', 0) > 10:
                summary['recommendations'].append("Implement enhanced authentication rate limiting")
            
            if summary['threats_by_type'].get('credential_theft', 0) > 5:
                summary['recommendations'].append("Review and enhance multi-factor authentication")
            
            if summary['active_campaigns'] > 0:
                summary['recommendations'].append("Coordinate response to active threat campaigns")
            
            if summary['threat_sources'] > 20:
                summary['recommendations'].append("Consider IP-based blocking for repeat offenders")
        
        return summary
    
    async def shutdown(self):
        """Gracefully shutdown the engine"""
        logging.info("Shutting down Identity Threat Detection Engine")
        
        if self.redis_client:
            await self.redis_client.close()
        
        logging.info("Identity Threat Detection Engine shutdown complete")


# Example usage and testing
async def example_usage():
    """Example usage of the Identity Threat Detection Engine"""
    
    # Initialize engine
    engine = IdentityThreatDetectionEngine(
        db_path="test_identity_threats.db",
        redis_url="redis://localhost:6379"
    )
    
    await engine.initialize()
    
    # Create sample events simulating various attack patterns
    sample_events = [
        # Brute force attack
        {
            'event_id': str(uuid.uuid4()),
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'user_id': 'victim_user',
            'source_ip': '192.168.1.100',
            'success': False,
            'action': 'login',
            'user_agent': 'Mozilla/5.0'
        },
        # Multiple failed attempts
        *[{
            'event_id': str(uuid.uuid4()),
            'timestamp': (datetime.now(timezone.utc) + timedelta(seconds=i*10)).isoformat(),
            'user_id': 'victim_user',
            'source_ip': '192.168.1.100',
            'success': False,
            'action': 'login',
            'user_agent': 'Mozilla/5.0'
        } for i in range(1, 12)],
        
        # Successful login after brute force
        {
            'event_id': str(uuid.uuid4()),
            'timestamp': (datetime.now(timezone.utc) + timedelta(minutes=15)).isoformat(),
            'user_id': 'victim_user',
            'source_ip': '192.168.1.100',
            'success': True,
            'action': 'login',
            'user_agent': 'Mozilla/5.0'
        },
        
        # Impossible travel
        {
            'event_id': str(uuid.uuid4()),
            'timestamp': (datetime.now(timezone.utc) + timedelta(minutes=20)).isoformat(),
            'user_id': 'victim_user',
            'source_ip': '10.0.0.50',
            'success': True,
            'action': 'login',
            'latitude': 51.5074,  # London
            'longitude': -0.1278,
            'user_agent': 'Mozilla/5.0'
        },
    ]
    
    # User profiles
    user_profiles = {
        'victim_user': {
            'user_id': 'victim_user',
            'normal_access_hours': list(range(9, 17)),
            'normal_applications': ['web-app', 'email'],
            'known_devices': ['device123'],
            'business_hours': {'start': 9, 'end': 17},
            'normal_resources': ['dashboard', 'reports'],
            'max_concurrent_sessions': 2
        }
    }
    
    # Add some threat intelligence indicators
    malicious_ip_indicator = ThreatIndicator(
        indicator_id=str(uuid.uuid4()),
        indicator_type='ip',
        indicator_value='192.168.1.100',
        threat_types=[ThreatType.BRUTE_FORCE, ThreatType.CREDENTIAL_THEFT],
        confidence=0.8,
        severity=ThreatSeverity.HIGH,
        source=ThreatIntelligenceSource.COMMERCIAL_FEED,
        first_seen=datetime.now(timezone.utc) - timedelta(days=1),
        last_seen=datetime.now(timezone.utc),
        description="Known malicious IP involved in credential attacks"
    )
    
    await engine.threat_intel.add_indicator(malicious_ip_indicator)
    
    # Detect threats
    threats = await engine.detect_threats(sample_events, user_profiles)
    
    print(f"Detected {len(threats)} threats:")
    for threat in threats:
        print(f"- {threat.threat_type.value}: {threat.description} (Confidence: {threat.confidence:.2f})")
        if threat.campaign_id:
            print(f"  Part of campaign: {threat.campaign_id}")
    
    # Get threat summary
    summary = await engine.get_threat_summary()
    print(f"\nThreat Summary:")
    print(f"Total Threats: {summary['total_threats']}")
    print(f"Active Campaigns: {summary['active_campaigns']}")
    print(f"Affected Users: {summary['affected_users']}")
    print(f"Recommendations: {summary['recommendations']}")
    
    await engine.shutdown()


if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Run example
    asyncio.run(example_usage())