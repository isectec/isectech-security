#!/usr/bin/env python3
# iSECTECH Behavioral Pattern Analyzer
# Production-grade behavioral analysis for entities and user activities

import numpy as np
import pandas as pd
import networkx as nx
import logging
import asyncio
import json
import yaml
import sqlite3
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional, Any, Set
from dataclasses import dataclass, asdict
from pathlib import Path
import pickle
import hashlib
from collections import defaultdict, Counter
import ipaddress

# Machine learning imports
from sklearn.cluster import DBSCAN, KMeans, AgglomerativeClustering
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.decomposition import PCA
from sklearn.metrics import silhouette_score
from sklearn.ensemble import IsolationForest
import joblib

# Graph analysis imports
import community as community_louvain
from scipy.spatial.distance import pdist, squareform
from scipy.cluster.hierarchy import dendrogram, linkage

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/nsm/behavioral-analysis.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class EntityProfile:
    """Comprehensive entity behavioral profile"""
    entity_id: str
    entity_type: str  # 'user', 'host', 'service', 'application'
    profile_data: Dict[str, Any]
    behavioral_vector: List[float]
    risk_score: float
    anomaly_score: float
    peer_group: Optional[str] = None
    last_updated: datetime = None
    confidence: float = 0.0
    
    # Behavioral patterns
    temporal_patterns: Dict[str, Any] = None
    communication_patterns: Dict[str, Any] = None
    access_patterns: Dict[str, Any] = None
    data_patterns: Dict[str, Any] = None
    
    # Risk factors
    risk_indicators: List[str] = None
    anomaly_indicators: List[str] = None
    
@dataclass
class BehavioralAnomaly:
    """Behavioral anomaly detection result"""
    entity_id: str
    entity_type: str
    anomaly_type: str
    timestamp: datetime
    description: str
    severity: str
    confidence: float
    risk_increase: float
    baseline_deviation: float
    
    # Context information
    affected_patterns: List[str] = None
    peer_comparison: Dict[str, Any] = None
    historical_context: Dict[str, Any] = None
    recommendations: List[str] = None

@dataclass
class CommunicationRelationship:
    """Relationship between entities based on communication"""
    source_entity: str
    target_entity: str
    relationship_type: str
    strength: float
    frequency: int
    first_seen: datetime
    last_seen: datetime
    protocols: Set[str] = None
    ports: Set[int] = None
    data_volume: int = 0

class EntityBehaviorProfiler:
    """Profile entity behavior patterns"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.min_activity_threshold = config.get('min_activity_threshold', 50)
        self.profile_window_days = config.get('profile_window_days', 30)
        
    def profile_user_behavior(self, user_id: str, activities: List[Dict[str, Any]]) -> EntityProfile:
        """Create comprehensive user behavioral profile"""
        if len(activities) < self.min_activity_threshold:
            logger.warning(f"Insufficient activity data for user {user_id}: {len(activities)} events")
            return self._create_minimal_profile(user_id, 'user')
        
        # Analyze temporal patterns
        temporal_patterns = self._analyze_temporal_patterns(activities)
        
        # Analyze access patterns
        access_patterns = self._analyze_access_patterns(activities)
        
        # Analyze communication patterns
        communication_patterns = self._analyze_communication_patterns(activities)
        
        # Analyze data patterns
        data_patterns = self._analyze_data_patterns(activities)
        
        # Create behavioral vector
        behavioral_vector = self._create_behavioral_vector({
            'temporal': temporal_patterns,
            'access': access_patterns,
            'communication': communication_patterns,
            'data': data_patterns
        })
        
        # Calculate base risk score
        risk_score = self._calculate_base_risk_score(activities, {
            'temporal': temporal_patterns,
            'access': access_patterns,
            'communication': communication_patterns,
            'data': data_patterns
        })
        
        # Identify risk indicators
        risk_indicators = self._identify_risk_indicators(activities, {
            'temporal': temporal_patterns,
            'access': access_patterns,
            'communication': communication_patterns,
            'data': data_patterns
        })
        
        profile = EntityProfile(
            entity_id=user_id,
            entity_type='user',
            profile_data={
                'total_activities': len(activities),
                'activity_timespan': self._calculate_timespan(activities),
                'unique_resources': len(set(a.get('resource', '') for a in activities)),
                'unique_hosts': len(set(a.get('host', '') for a in activities)),
                'unique_applications': len(set(a.get('application', '') for a in activities))
            },
            behavioral_vector=behavioral_vector,
            risk_score=risk_score,
            anomaly_score=0.0,  # Will be calculated by anomaly detector
            temporal_patterns=temporal_patterns,
            communication_patterns=communication_patterns,
            access_patterns=access_patterns,
            data_patterns=data_patterns,
            risk_indicators=risk_indicators,
            last_updated=datetime.now(),
            confidence=min(1.0, len(activities) / 1000)  # Higher confidence with more data
        )
        
        return profile
    
    def profile_host_behavior(self, host_id: str, network_flows: List[Dict[str, Any]]) -> EntityProfile:
        """Create comprehensive host behavioral profile"""
        if len(network_flows) < self.min_activity_threshold:
            return self._create_minimal_profile(host_id, 'host')
        
        # Analyze communication patterns
        communication_patterns = self._analyze_host_communication_patterns(network_flows)
        
        # Analyze service patterns
        service_patterns = self._analyze_service_patterns(network_flows)
        
        # Analyze temporal patterns
        temporal_patterns = self._analyze_temporal_patterns(network_flows)
        
        # Analyze data transfer patterns
        data_patterns = self._analyze_host_data_patterns(network_flows)
        
        # Create behavioral vector
        behavioral_vector = self._create_behavioral_vector({
            'communication': communication_patterns,
            'service': service_patterns,
            'temporal': temporal_patterns,
            'data': data_patterns
        })
        
        # Calculate risk score
        risk_score = self._calculate_host_risk_score(network_flows, {
            'communication': communication_patterns,
            'service': service_patterns,
            'temporal': temporal_patterns,
            'data': data_patterns
        })
        
        # Identify risk indicators
        risk_indicators = self._identify_host_risk_indicators(network_flows, {
            'communication': communication_patterns,
            'service': service_patterns,
            'temporal': temporal_patterns,
            'data': data_patterns
        })
        
        profile = EntityProfile(
            entity_id=host_id,
            entity_type='host',
            profile_data={
                'total_flows': len(network_flows),
                'unique_destinations': len(set(f.get('destination_ip', '') for f in network_flows)),
                'unique_sources': len(set(f.get('source_ip', '') for f in network_flows)),
                'unique_ports': len(set(f.get('destination_port', 0) for f in network_flows)),
                'total_bytes': sum(f.get('bytes_sent', 0) + f.get('bytes_received', 0) for f in network_flows)
            },
            behavioral_vector=behavioral_vector,
            risk_score=risk_score,
            anomaly_score=0.0,
            communication_patterns=communication_patterns,
            access_patterns=service_patterns,
            data_patterns=data_patterns,
            temporal_patterns=temporal_patterns,
            risk_indicators=risk_indicators,
            last_updated=datetime.now(),
            confidence=min(1.0, len(network_flows) / 10000)
        )
        
        return profile
    
    def _analyze_temporal_patterns(self, activities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze temporal behavior patterns"""
        if not activities:
            return {}
        
        timestamps = []
        for activity in activities:
            if 'timestamp' in activity:
                if isinstance(activity['timestamp'], str):
                    timestamps.append(datetime.fromisoformat(activity['timestamp'].replace('Z', '+00:00')))
                else:
                    timestamps.append(activity['timestamp'])
        
        if not timestamps:
            return {}
        
        # Hour of day patterns
        hours = [ts.hour for ts in timestamps]
        hour_distribution = dict(Counter(hours))
        
        # Day of week patterns
        weekdays = [ts.weekday() for ts in timestamps]
        weekday_distribution = dict(Counter(weekdays))
        
        # Session patterns
        sessions = self._identify_sessions(timestamps)
        
        return {
            'active_hours': {
                'distribution': hour_distribution,
                'peak_hours': sorted(hour_distribution.items(), key=lambda x: x[1], reverse=True)[:3],
                'activity_spread': len(hour_distribution) / 24.0
            },
            'active_weekdays': {
                'distribution': weekday_distribution,
                'working_days_ratio': sum(weekday_distribution.get(i, 0) for i in range(5)) / len(timestamps),
                'weekend_ratio': sum(weekday_distribution.get(i, 0) for i in [5, 6]) / len(timestamps)
            },
            'sessions': {
                'total_sessions': len(sessions),
                'avg_session_duration': np.mean([s['duration'] for s in sessions]) if sessions else 0,
                'avg_session_activity': np.mean([s['activity_count'] for s in sessions]) if sessions else 0
            },
            'regularity': {
                'time_variance': np.var(hours) if hours else 0,
                'day_variance': np.var(weekdays) if weekdays else 0
            }
        }
    
    def _analyze_access_patterns(self, activities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze access behavior patterns"""
        if not activities:
            return {}
        
        resources = [a.get('resource', '') for a in activities if a.get('resource')]
        hosts = [a.get('host', '') for a in activities if a.get('host')]
        applications = [a.get('application', '') for a in activities if a.get('application')]
        actions = [a.get('action', '') for a in activities if a.get('action')]
        
        return {
            'resource_access': {
                'unique_resources': len(set(resources)),
                'resource_diversity': len(set(resources)) / max(len(activities), 1),
                'top_resources': dict(Counter(resources).most_common(10)),
                'access_concentration': max(Counter(resources).values()) / len(resources) if resources else 0
            },
            'host_access': {
                'unique_hosts': len(set(hosts)),
                'host_diversity': len(set(hosts)) / max(len(activities), 1),
                'top_hosts': dict(Counter(hosts).most_common(10))
            },
            'application_usage': {
                'unique_applications': len(set(applications)),
                'app_diversity': len(set(applications)) / max(len(activities), 1),
                'top_applications': dict(Counter(applications).most_common(10))
            },
            'action_patterns': {
                'action_distribution': dict(Counter(actions)),
                'read_write_ratio': Counter(actions).get('read', 0) / max(Counter(actions).get('write', 1), 1)
            }
        }
    
    def _analyze_communication_patterns(self, activities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze communication behavior patterns"""
        if not activities:
            return {}
        
        # Extract communication data
        sources = [a.get('source_ip', '') for a in activities if a.get('source_ip')]
        destinations = [a.get('destination_ip', '') for a in activities if a.get('destination_ip')]
        ports = [a.get('port', 0) for a in activities if a.get('port')]
        protocols = [a.get('protocol', '') for a in activities if a.get('protocol')]
        
        return {
            'communication_diversity': {
                'unique_sources': len(set(sources)),
                'unique_destinations': len(set(destinations)),
                'unique_ports': len(set(ports)),
                'unique_protocols': len(set(protocols))
            },
            'communication_patterns': {
                'top_destinations': dict(Counter(destinations).most_common(10)),
                'top_ports': dict(Counter(ports).most_common(10)),
                'protocol_distribution': dict(Counter(protocols))
            },
            'network_behavior': {
                'internal_external_ratio': self._calculate_internal_external_ratio(destinations),
                'port_scanning_indicators': self._detect_port_scanning(activities),
                'communication_regularity': self._calculate_communication_regularity(activities)
            }
        }
    
    def _analyze_data_patterns(self, activities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze data transfer behavior patterns"""
        if not activities:
            return {}
        
        data_sizes = [a.get('data_size', 0) for a in activities if a.get('data_size')]
        
        if not data_sizes:
            return {}
        
        return {
            'data_volume': {
                'total_data': sum(data_sizes),
                'avg_data_size': np.mean(data_sizes),
                'data_variance': np.var(data_sizes),
                'max_transfer': max(data_sizes),
                'min_transfer': min(data_sizes)
            },
            'transfer_patterns': {
                'large_transfer_ratio': sum(1 for size in data_sizes if size > np.percentile(data_sizes, 95)) / len(data_sizes),
                'small_transfer_ratio': sum(1 for size in data_sizes if size < np.percentile(data_sizes, 25)) / len(data_sizes)
            }
        }
    
    def _analyze_host_communication_patterns(self, flows: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze host communication patterns"""
        if not flows:
            return {}
        
        destinations = [f.get('destination_ip', '') for f in flows]
        sources = [f.get('source_ip', '') for f in flows]
        ports = [f.get('destination_port', 0) for f in flows]
        protocols = [f.get('protocol', '') for f in flows]
        
        return {
            'communication_breadth': {
                'unique_destinations': len(set(destinations)),
                'unique_sources': len(set(sources)),
                'destination_entropy': self._calculate_entropy(destinations),
                'source_entropy': self._calculate_entropy(sources)
            },
            'service_patterns': {
                'unique_ports': len(set(ports)),
                'port_distribution': dict(Counter(ports)),
                'protocol_distribution': dict(Counter(protocols)),
                'well_known_ports_ratio': sum(1 for p in ports if p < 1024) / len(ports) if ports else 0
            },
            'traffic_characteristics': {
                'internal_ratio': self._calculate_internal_ratio(destinations + sources),
                'bidirectional_flows': self._count_bidirectional_flows(flows)
            }
        }
    
    def _analyze_service_patterns(self, flows: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze service usage patterns"""
        if not flows:
            return {}
        
        services = [f.get('application', '') for f in flows if f.get('application')]
        ports = [f.get('destination_port', 0) for f in flows]
        
        # Map ports to services
        common_services = {
            80: 'HTTP', 443: 'HTTPS', 53: 'DNS', 22: 'SSH',
            21: 'FTP', 25: 'SMTP', 110: 'POP3', 143: 'IMAP',
            3389: 'RDP', 1433: 'MSSQL', 3306: 'MySQL'
        }
        
        inferred_services = [common_services.get(port, f'Port-{port}') for port in ports]
        
        return {
            'service_usage': {
                'identified_services': dict(Counter(services)),
                'inferred_services': dict(Counter(inferred_services)),
                'service_diversity': len(set(services + inferred_services))
            },
            'service_behavior': {
                'web_traffic_ratio': (ports.count(80) + ports.count(443)) / len(ports) if ports else 0,
                'admin_services_ratio': sum(1 for p in ports if p in [22, 3389, 23]) / len(ports) if ports else 0,
                'database_services_ratio': sum(1 for p in ports if p in [1433, 3306, 5432, 1521]) / len(ports) if ports else 0
            }
        }
    
    def _analyze_host_data_patterns(self, flows: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze host data transfer patterns"""
        if not flows:
            return {}
        
        bytes_sent = [f.get('bytes_sent', 0) for f in flows]
        bytes_received = [f.get('bytes_received', 0) for f in flows]
        total_bytes = [s + r for s, r in zip(bytes_sent, bytes_received)]
        
        if not total_bytes:
            return {}
        
        return {
            'data_volume': {
                'total_sent': sum(bytes_sent),
                'total_received': sum(bytes_received),
                'total_data': sum(total_bytes),
                'send_receive_ratio': sum(bytes_sent) / max(sum(bytes_received), 1)
            },
            'transfer_patterns': {
                'avg_flow_size': np.mean(total_bytes),
                'data_variance': np.var(total_bytes),
                'large_flows_ratio': sum(1 for b in total_bytes if b > np.percentile(total_bytes, 95)) / len(total_bytes),
                'flow_size_distribution': {
                    'small': sum(1 for b in total_bytes if b < 1024),
                    'medium': sum(1 for b in total_bytes if 1024 <= b < 1048576),
                    'large': sum(1 for b in total_bytes if b >= 1048576)
                }
            }
        }
    
    def _create_behavioral_vector(self, patterns: Dict[str, Any]) -> List[float]:
        """Create numerical behavioral vector from patterns"""
        vector = []
        
        # Extract numerical features from patterns
        for category, pattern_data in patterns.items():
            if isinstance(pattern_data, dict):
                vector.extend(self._extract_numerical_features(pattern_data))
        
        # Normalize vector
        if vector:
            max_val = max(vector) if max(vector) > 0 else 1
            vector = [v / max_val for v in vector]
        
        return vector
    
    def _extract_numerical_features(self, data: Dict[str, Any], max_depth: int = 3) -> List[float]:
        """Extract numerical features from nested dictionary"""
        features = []
        
        if max_depth <= 0:
            return features
        
        for key, value in data.items():
            if isinstance(value, (int, float)):
                features.append(float(value))
            elif isinstance(value, dict):
                features.extend(self._extract_numerical_features(value, max_depth - 1))
            elif isinstance(value, list) and value and isinstance(value[0], (int, float)):
                features.extend([len(value), np.mean(value), np.std(value)])
        
        return features
    
    def _calculate_base_risk_score(self, activities: List[Dict[str, Any]], patterns: Dict[str, Any]) -> float:
        """Calculate base risk score for entity"""
        risk_factors = []
        
        # Temporal risk factors
        temporal = patterns.get('temporal', {})
        if temporal:
            # Off-hours activity
            active_hours = temporal.get('active_hours', {})
            off_hours_activity = sum(active_hours.get('distribution', {}).get(hour, 0) 
                                   for hour in [22, 23, 0, 1, 2, 3, 4, 5]) / max(len(activities), 1)
            risk_factors.append(off_hours_activity * 0.3)
            
            # Weekend activity
            weekday_patterns = temporal.get('active_weekdays', {})
            weekend_ratio = weekday_patterns.get('weekend_ratio', 0)
            risk_factors.append(weekend_ratio * 0.2)
        
        # Access pattern risk factors
        access = patterns.get('access', {})
        if access:
            # Resource concentration
            resource_access = access.get('resource_access', {})
            concentration = resource_access.get('access_concentration', 0)
            risk_factors.append(concentration * 0.2)
        
        # Communication risk factors
        communication = patterns.get('communication', {})
        if communication:
            # External communication ratio
            network_behavior = communication.get('network_behavior', {})
            external_ratio = 1 - network_behavior.get('internal_external_ratio', 0.5)
            risk_factors.append(external_ratio * 0.4)
            
            # Port scanning indicators
            port_scanning = network_behavior.get('port_scanning_indicators', 0)
            risk_factors.append(port_scanning * 0.6)
        
        # Data pattern risk factors
        data = patterns.get('data', {})
        if data:
            # Large transfer ratio
            transfer_patterns = data.get('transfer_patterns', {})
            large_transfer_ratio = transfer_patterns.get('large_transfer_ratio', 0)
            risk_factors.append(large_transfer_ratio * 0.3)
        
        # Calculate weighted average
        return min(1.0, np.mean(risk_factors)) if risk_factors else 0.0
    
    def _calculate_host_risk_score(self, flows: List[Dict[str, Any]], patterns: Dict[str, Any]) -> float:
        """Calculate risk score for host entity"""
        risk_factors = []
        
        # Communication breadth risk
        communication = patterns.get('communication', {})
        if communication:
            breadth = communication.get('communication_breadth', {})
            # High number of unique destinations might indicate scanning
            unique_destinations = breadth.get('unique_destinations', 0)
            if unique_destinations > 100:
                risk_factors.append(min(1.0, unique_destinations / 1000))
        
        # Service pattern risks
        service = patterns.get('service', {})
        if service:
            behavior = service.get('service_behavior', {})
            # High admin services usage
            admin_ratio = behavior.get('admin_services_ratio', 0)
            risk_factors.append(admin_ratio * 0.5)
        
        # Data transfer risks
        data = patterns.get('data', {})
        if data:
            volume = data.get('data_volume', {})
            # Unusual send/receive ratio
            ratio = volume.get('send_receive_ratio', 1)
            if ratio > 10 or ratio < 0.1:  # Very imbalanced
                risk_factors.append(0.4)
        
        return min(1.0, np.mean(risk_factors)) if risk_factors else 0.0
    
    def _identify_risk_indicators(self, activities: List[Dict[str, Any]], patterns: Dict[str, Any]) -> List[str]:
        """Identify specific risk indicators"""
        indicators = []
        
        # Check for off-hours activity
        temporal = patterns.get('temporal', {})
        if temporal:
            off_hours = sum(temporal.get('active_hours', {}).get('distribution', {}).get(hour, 0) 
                          for hour in [22, 23, 0, 1, 2, 3, 4, 5])
            if off_hours > len(activities) * 0.3:
                indicators.append("High off-hours activity")
        
        # Check for unusual access patterns
        access = patterns.get('access', {})
        if access:
            concentration = access.get('resource_access', {}).get('access_concentration', 0)
            if concentration > 0.8:
                indicators.append("High resource access concentration")
        
        # Check for communication anomalies
        communication = patterns.get('communication', {})
        if communication:
            port_scanning = communication.get('network_behavior', {}).get('port_scanning_indicators', 0)
            if port_scanning > 0.5:
                indicators.append("Potential port scanning behavior")
        
        return indicators
    
    def _identify_host_risk_indicators(self, flows: List[Dict[str, Any]], patterns: Dict[str, Any]) -> List[str]:
        """Identify host-specific risk indicators"""
        indicators = []
        
        # Check for scanning behavior
        communication = patterns.get('communication', {})
        if communication:
            unique_destinations = communication.get('communication_breadth', {}).get('unique_destinations', 0)
            if unique_destinations > 500:
                indicators.append("High destination diversity (potential scanning)")
        
        # Check for unusual service usage
        service = patterns.get('service', {})
        if service:
            admin_ratio = service.get('service_behavior', {}).get('admin_services_ratio', 0)
            if admin_ratio > 0.3:
                indicators.append("High administrative service usage")
        
        return indicators
    
    def _create_minimal_profile(self, entity_id: str, entity_type: str) -> EntityProfile:
        """Create minimal profile for entities with insufficient data"""
        return EntityProfile(
            entity_id=entity_id,
            entity_type=entity_type,
            profile_data={'insufficient_data': True},
            behavioral_vector=[],
            risk_score=0.5,  # Neutral risk
            anomaly_score=0.0,
            last_updated=datetime.now(),
            confidence=0.0
        )
    
    def _identify_sessions(self, timestamps: List[datetime]) -> List[Dict[str, Any]]:
        """Identify user sessions from timestamps"""
        if not timestamps:
            return []
        
        sorted_timestamps = sorted(timestamps)
        sessions = []
        current_session = [sorted_timestamps[0]]
        session_threshold = timedelta(hours=1)  # 1 hour gap = new session
        
        for i in range(1, len(sorted_timestamps)):
            time_gap = sorted_timestamps[i] - sorted_timestamps[i-1]
            
            if time_gap <= session_threshold:
                current_session.append(sorted_timestamps[i])
            else:
                # End current session, start new one
                if len(current_session) > 1:
                    sessions.append({
                        'start_time': current_session[0],
                        'end_time': current_session[-1],
                        'duration': (current_session[-1] - current_session[0]).total_seconds() / 3600,
                        'activity_count': len(current_session)
                    })
                current_session = [sorted_timestamps[i]]
        
        # Add last session
        if len(current_session) > 1:
            sessions.append({
                'start_time': current_session[0],
                'end_time': current_session[-1],
                'duration': (current_session[-1] - current_session[0]).total_seconds() / 3600,
                'activity_count': len(current_session)
            })
        
        return sessions
    
    def _calculate_timespan(self, activities: List[Dict[str, Any]]) -> float:
        """Calculate timespan of activities in hours"""
        if not activities:
            return 0.0
        
        timestamps = []
        for activity in activities:
            if 'timestamp' in activity:
                if isinstance(activity['timestamp'], str):
                    timestamps.append(datetime.fromisoformat(activity['timestamp'].replace('Z', '+00:00')))
                else:
                    timestamps.append(activity['timestamp'])
        
        if len(timestamps) < 2:
            return 0.0
        
        return (max(timestamps) - min(timestamps)).total_seconds() / 3600
    
    def _calculate_internal_external_ratio(self, destinations: List[str]) -> float:
        """Calculate ratio of internal to total destinations"""
        if not destinations:
            return 0.5
        
        internal_count = sum(1 for dest in destinations if self._is_internal_ip(dest))
        return internal_count / len(destinations)
    
    def _calculate_internal_ratio(self, ips: List[str]) -> float:
        """Calculate ratio of internal IPs"""
        if not ips:
            return 0.5
        
        internal_count = sum(1 for ip in ips if self._is_internal_ip(ip))
        return internal_count / len(ips)
    
    def _is_internal_ip(self, ip_str: str) -> bool:
        """Check if IP is internal"""
        try:
            ip = ipaddress.IPv4Address(ip_str)
            private_networks = [
                ipaddress.IPv4Network('10.0.0.0/8'),
                ipaddress.IPv4Network('172.16.0.0/12'),
                ipaddress.IPv4Network('192.168.0.0/16'),
                ipaddress.IPv4Network('127.0.0.0/8')
            ]
            return any(ip in network for network in private_networks)
        except:
            return False
    
    def _detect_port_scanning(self, activities: List[Dict[str, Any]]) -> float:
        """Detect port scanning behavior"""
        ports = [a.get('port', 0) for a in activities if a.get('port')]
        
        if not ports:
            return 0.0
        
        unique_ports = len(set(ports))
        total_connections = len(ports)
        
        # High port diversity might indicate scanning
        port_diversity = unique_ports / total_connections
        
        # Sequential port access pattern
        sorted_ports = sorted(set(ports))
        sequential_ratio = 0.0
        
        if len(sorted_ports) > 1:
            sequential_count = sum(1 for i in range(1, len(sorted_ports)) 
                                 if sorted_ports[i] - sorted_ports[i-1] == 1)
            sequential_ratio = sequential_count / (len(sorted_ports) - 1)
        
        # Combine indicators
        scanning_score = (port_diversity * 0.7 + sequential_ratio * 0.3)
        
        return min(1.0, scanning_score)
    
    def _calculate_communication_regularity(self, activities: List[Dict[str, Any]]) -> float:
        """Calculate regularity of communication patterns"""
        destinations = [a.get('destination_ip', '') for a in activities if a.get('destination_ip')]
        
        if not destinations:
            return 0.0
        
        # Calculate entropy of destination distribution
        return self._calculate_entropy(destinations)
    
    def _calculate_entropy(self, data: List[str]) -> float:
        """Calculate Shannon entropy of data distribution"""
        if not data:
            return 0.0
        
        counts = Counter(data)
        total = len(data)
        entropy = 0.0
        
        for count in counts.values():
            probability = count / total
            if probability > 0:
                entropy -= probability * np.log2(probability)
        
        # Normalize by maximum possible entropy
        max_entropy = np.log2(len(counts)) if len(counts) > 1 else 1
        
        return entropy / max_entropy if max_entropy > 0 else 0.0
    
    def _count_bidirectional_flows(self, flows: List[Dict[str, Any]]) -> float:
        """Count bidirectional communication flows"""
        if not flows:
            return 0.0
        
        # Create flow pairs
        flow_pairs = set()
        reverse_pairs = set()
        
        for flow in flows:
            src = flow.get('source_ip', '')
            dst = flow.get('destination_ip', '')
            port = flow.get('destination_port', 0)
            
            flow_key = (src, dst, port)
            reverse_key = (dst, src, port)
            
            flow_pairs.add(flow_key)
            if reverse_key in flow_pairs:
                reverse_pairs.add(flow_key)
        
        return len(reverse_pairs) / len(flow_pairs) if flow_pairs else 0.0

class PeerGroupAnalyzer:
    """Analyze peer groups and comparative behavior"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.min_group_size = config.get('min_group_size', 5)
        self.max_group_size = config.get('max_group_size', 50)
        self.similarity_threshold = config.get('similarity_threshold', 0.8)
        
    def create_peer_groups(self, profiles: List[EntityProfile]) -> Dict[str, List[str]]:
        """Create peer groups based on behavioral similarity"""
        if len(profiles) < self.min_group_size:
            logger.warning("Insufficient profiles for peer group analysis")
            return {}
        
        # Filter profiles with sufficient data
        valid_profiles = [p for p in profiles if p.behavioral_vector and p.confidence > 0.3]
        
        if len(valid_profiles) < self.min_group_size:
            return {}
        
        # Create feature matrix
        feature_matrix = []
        entity_ids = []
        
        for profile in valid_profiles:
            if len(profile.behavioral_vector) > 0:
                feature_matrix.append(profile.behavioral_vector)
                entity_ids.append(profile.entity_id)
        
        if not feature_matrix:
            return {}
        
        # Normalize features
        scaler = StandardScaler()
        normalized_features = scaler.fit_transform(feature_matrix)
        
        # Perform clustering
        groups = self._perform_clustering(normalized_features, entity_ids)
        
        return groups
    
    def _perform_clustering(self, features: np.ndarray, entity_ids: List[str]) -> Dict[str, List[str]]:
        """Perform clustering to identify peer groups"""
        groups = {}
        
        # Try different clustering algorithms
        clustering_results = {}
        
        # DBSCAN clustering
        try:
            dbscan = DBSCAN(eps=0.5, min_samples=self.min_group_size)
            dbscan_labels = dbscan.fit_predict(features)
            clustering_results['dbscan'] = dbscan_labels
        except Exception as e:
            logger.warning(f"DBSCAN clustering failed: {e}")
        
        # K-Means clustering
        try:
            # Estimate optimal number of clusters
            n_clusters = min(8, max(2, len(entity_ids) // 10))
            kmeans = KMeans(n_clusters=n_clusters, random_state=42, n_init=10)
            kmeans_labels = kmeans.fit_predict(features)
            clustering_results['kmeans'] = kmeans_labels
        except Exception as e:
            logger.warning(f"K-Means clustering failed: {e}")
        
        # Hierarchical clustering
        try:
            n_clusters = min(8, max(2, len(entity_ids) // 10))
            hierarchical = AgglomerativeClustering(n_clusters=n_clusters)
            hierarchical_labels = hierarchical.fit_predict(features)
            clustering_results['hierarchical'] = hierarchical_labels
        except Exception as e:
            logger.warning(f"Hierarchical clustering failed: {e}")
        
        # Select best clustering result
        best_method = self._select_best_clustering(features, clustering_results)
        
        if best_method:
            labels = clustering_results[best_method]
            
            # Create groups
            for i, label in enumerate(labels):
                if label == -1:  # Noise in DBSCAN
                    continue
                
                group_name = f"{best_method}_group_{label}"
                if group_name not in groups:
                    groups[group_name] = []
                
                groups[group_name].append(entity_ids[i])
            
            # Filter groups by size
            groups = {name: members for name, members in groups.items() 
                     if self.min_group_size <= len(members) <= self.max_group_size}
        
        return groups
    
    def _select_best_clustering(self, features: np.ndarray, results: Dict[str, np.ndarray]) -> Optional[str]:
        """Select best clustering method based on silhouette score"""
        best_score = -1
        best_method = None
        
        for method, labels in results.items():
            try:
                # Skip if all points are in same cluster or all are noise
                unique_labels = set(labels)
                if len(unique_labels) <= 1:
                    continue
                
                # Remove noise points for silhouette calculation
                valid_indices = labels != -1
                if np.sum(valid_indices) < 2:
                    continue
                
                valid_features = features[valid_indices]
                valid_labels = labels[valid_indices]
                
                if len(set(valid_labels)) > 1:
                    score = silhouette_score(valid_features, valid_labels)
                    if score > best_score:
                        best_score = score
                        best_method = method
            except Exception as e:
                logger.warning(f"Error calculating silhouette score for {method}: {e}")
        
        return best_method
    
    def compare_to_peer_group(self, entity_profile: EntityProfile, 
                             peer_group_profiles: List[EntityProfile]) -> Dict[str, Any]:
        """Compare entity behavior to its peer group"""
        if not peer_group_profiles or not entity_profile.behavioral_vector:
            return {}
        
        # Calculate peer group statistics
        peer_vectors = [p.behavioral_vector for p in peer_group_profiles 
                       if p.behavioral_vector and len(p.behavioral_vector) == len(entity_profile.behavioral_vector)]
        
        if not peer_vectors:
            return {}
        
        peer_matrix = np.array(peer_vectors)
        entity_vector = np.array(entity_profile.behavioral_vector)
        
        # Calculate statistics
        peer_mean = np.mean(peer_matrix, axis=0)
        peer_std = np.std(peer_matrix, axis=0)
        
        # Calculate deviations
        deviations = np.abs(entity_vector - peer_mean) / np.maximum(peer_std, 0.001)
        
        # Identify significant deviations
        significant_deviations = deviations > 2.0  # 2 sigma threshold
        
        return {
            'peer_group_size': len(peer_group_profiles),
            'behavioral_similarity': 1.0 - np.mean(deviations),
            'significant_deviations': np.sum(significant_deviations),
            'deviation_score': np.mean(deviations),
            'max_deviation': np.max(deviations),
            'deviation_features': significant_deviations.tolist(),
            'peer_risk_percentile': self._calculate_risk_percentile(entity_profile, peer_group_profiles)
        }
    
    def _calculate_risk_percentile(self, entity_profile: EntityProfile, 
                                  peer_group_profiles: List[EntityProfile]) -> float:
        """Calculate risk percentile within peer group"""
        peer_risks = [p.risk_score for p in peer_group_profiles if p.risk_score is not None]
        
        if not peer_risks:
            return 0.5
        
        entity_risk = entity_profile.risk_score
        percentile = np.percentile(peer_risks, entity_risk * 100)
        
        return percentile

class CommunicationGraphAnalyzer:
    """Analyze communication relationships using graph theory"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.graph = nx.DiGraph()
        
    def build_communication_graph(self, flows: List[Dict[str, Any]]) -> nx.DiGraph:
        """Build communication graph from network flows"""
        self.graph.clear()
        
        # Aggregate flows by source-destination pairs
        flow_aggregates = defaultdict(lambda: {
            'count': 0,
            'total_bytes': 0,
            'protocols': set(),
            'ports': set(),
            'first_seen': None,
            'last_seen': None
        })
        
        for flow in flows:
            src = flow.get('source_ip', '')
            dst = flow.get('destination_ip', '')
            
            if not src or not dst:
                continue
            
            key = (src, dst)
            aggregate = flow_aggregates[key]
            
            aggregate['count'] += 1
            aggregate['total_bytes'] += flow.get('bytes_sent', 0) + flow.get('bytes_received', 0)
            
            if flow.get('protocol'):
                aggregate['protocols'].add(flow['protocol'])
            
            if flow.get('destination_port'):
                aggregate['ports'].add(flow['destination_port'])
            
            timestamp = flow.get('timestamp')
            if timestamp:
                if isinstance(timestamp, str):
                    timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                
                if not aggregate['first_seen'] or timestamp < aggregate['first_seen']:
                    aggregate['first_seen'] = timestamp
                
                if not aggregate['last_seen'] or timestamp > aggregate['last_seen']:
                    aggregate['last_seen'] = timestamp
        
        # Add edges to graph
        for (src, dst), aggregate in flow_aggregates.items():
            weight = aggregate['total_bytes'] / max(aggregate['count'], 1)  # Average bytes per flow
            
            self.graph.add_edge(src, dst, 
                              weight=weight,
                              count=aggregate['count'],
                              total_bytes=aggregate['total_bytes'],
                              protocols=list(aggregate['protocols']),
                              ports=list(aggregate['ports']),
                              first_seen=aggregate['first_seen'],
                              last_seen=aggregate['last_seen'])
        
        return self.graph
    
    def analyze_communication_patterns(self) -> Dict[str, Any]:
        """Analyze communication patterns in the graph"""
        if not self.graph.nodes():
            return {}
        
        analysis = {}
        
        # Basic graph metrics
        analysis['basic_metrics'] = {
            'num_nodes': self.graph.number_of_nodes(),
            'num_edges': self.graph.number_of_edges(),
            'density': nx.density(self.graph),
            'is_connected': nx.is_connected(self.graph.to_undirected())
        }
        
        # Centrality measures
        analysis['centrality'] = self._calculate_centrality_measures()
        
        # Community detection
        analysis['communities'] = self._detect_communities()
        
        # Anomalous nodes
        analysis['anomalous_nodes'] = self._identify_anomalous_nodes()
        
        # Communication hubs
        analysis['communication_hubs'] = self._identify_communication_hubs()
        
        return analysis
    
    def _calculate_centrality_measures(self) -> Dict[str, Any]:
        """Calculate various centrality measures"""
        centrality = {}
        
        try:
            # Degree centrality
            in_degree = dict(self.graph.in_degree())
            out_degree = dict(self.graph.out_degree())
            
            centrality['top_receivers'] = sorted(in_degree.items(), key=lambda x: x[1], reverse=True)[:10]
            centrality['top_senders'] = sorted(out_degree.items(), key=lambda x: x[1], reverse=True)[:10]
            
            # Betweenness centrality (for smaller graphs)
            if self.graph.number_of_nodes() < 1000:
                betweenness = nx.betweenness_centrality(self.graph)
                centrality['top_betweenness'] = sorted(betweenness.items(), key=lambda x: x[1], reverse=True)[:10]
            
            # PageRank
            pagerank = nx.pagerank(self.graph)
            centrality['top_pagerank'] = sorted(pagerank.items(), key=lambda x: x[1], reverse=True)[:10]
            
        except Exception as e:
            logger.warning(f"Error calculating centrality measures: {e}")
        
        return centrality
    
    def _detect_communities(self) -> Dict[str, Any]:
        """Detect communities in the communication graph"""
        communities = {}
        
        try:
            # Convert to undirected graph for community detection
            undirected_graph = self.graph.to_undirected()
            
            # Louvain community detection
            partition = community_louvain.best_partition(undirected_graph)
            
            # Group nodes by community
            community_groups = defaultdict(list)
            for node, community_id in partition.items():
                community_groups[community_id].append(node)
            
            communities['louvain'] = dict(community_groups)
            communities['num_communities'] = len(community_groups)
            communities['modularity'] = community_louvain.modularity(partition, undirected_graph)
            
        except Exception as e:
            logger.warning(f"Error detecting communities: {e}")
        
        return communities
    
    def _identify_anomalous_nodes(self) -> List[Dict[str, Any]]:
        """Identify nodes with anomalous communication patterns"""
        anomalous_nodes = []
        
        try:
            # Calculate node statistics
            node_stats = {}
            
            for node in self.graph.nodes():
                in_degree = self.graph.in_degree(node)
                out_degree = self.graph.out_degree(node)
                
                # Calculate total communication volume
                total_bytes_in = sum(self.graph[pred][node].get('total_bytes', 0) 
                                   for pred in self.graph.predecessors(node))
                total_bytes_out = sum(self.graph[node][succ].get('total_bytes', 0) 
                                    for succ in self.graph.successors(node))
                
                node_stats[node] = {
                    'in_degree': in_degree,
                    'out_degree': out_degree,
                    'total_degree': in_degree + out_degree,
                    'bytes_in': total_bytes_in,
                    'bytes_out': total_bytes_out,
                    'total_bytes': total_bytes_in + total_bytes_out
                }
            
            # Identify outliers using statistical methods
            for metric in ['total_degree', 'total_bytes']:
                values = [stats[metric] for stats in node_stats.values()]
                
                if not values:
                    continue
                
                threshold = np.percentile(values, 95)  # Top 5% as anomalous
                
                for node, stats in node_stats.items():
                    if stats[metric] > threshold:
                        anomalous_nodes.append({
                            'node': node,
                            'anomaly_type': f'high_{metric}',
                            'value': stats[metric],
                            'threshold': threshold,
                            'percentile': np.percentile(values, stats[metric] / max(values) * 100)
                        })
        
        except Exception as e:
            logger.warning(f"Error identifying anomalous nodes: {e}")
        
        return anomalous_nodes
    
    def _identify_communication_hubs(self) -> List[Dict[str, Any]]:
        """Identify major communication hubs"""
        hubs = []
        
        try:
            # Calculate hub scores
            hub_scores = {}
            
            for node in self.graph.nodes():
                # Hub score based on degree and data volume
                in_degree = self.graph.in_degree(node)
                out_degree = self.graph.out_degree(node)
                
                total_bytes = sum(self.graph[pred][node].get('total_bytes', 0) 
                                for pred in self.graph.predecessors(node))
                total_bytes += sum(self.graph[node][succ].get('total_bytes', 0) 
                                 for succ in self.graph.successors(node))
                
                # Normalize scores
                degree_score = (in_degree + out_degree) / max(self.graph.number_of_nodes(), 1)
                volume_score = total_bytes / max(sum(self.graph[u][v].get('total_bytes', 0) 
                                                   for u, v in self.graph.edges()), 1)
                
                hub_scores[node] = degree_score * 0.5 + volume_score * 0.5
            
            # Sort by hub score
            sorted_hubs = sorted(hub_scores.items(), key=lambda x: x[1], reverse=True)
            
            # Take top hubs
            for node, score in sorted_hubs[:10]:
                hubs.append({
                    'node': node,
                    'hub_score': score,
                    'in_degree': self.graph.in_degree(node),
                    'out_degree': self.graph.out_degree(node),
                    'is_internal': self._is_internal_ip(node)
                })
        
        except Exception as e:
            logger.warning(f"Error identifying communication hubs: {e}")
        
        return hubs
    
    def _is_internal_ip(self, ip_str: str) -> bool:
        """Check if IP is internal"""
        try:
            ip = ipaddress.IPv4Address(ip_str)
            private_networks = [
                ipaddress.IPv4Network('10.0.0.0/8'),
                ipaddress.IPv4Network('172.16.0.0/12'),
                ipaddress.IPv4Network('192.168.0.0/16'),
                ipaddress.IPv4Network('127.0.0.0/8')
            ]
            return any(ip in network for network in private_networks)
        except:
            return False

class BehavioralPatternAnalyzer:
    """Main behavioral pattern analysis engine"""
    
    def __init__(self, config_path: str = "/etc/nsm/behavioral-analysis.yaml"):
        self.config_path = config_path
        self.config = self._load_config()
        
        # Initialize components
        self.profiler = EntityBehaviorProfiler(self.config.get('profiler', {}))
        self.peer_analyzer = PeerGroupAnalyzer(self.config.get('peer_groups', {}))
        self.graph_analyzer = CommunicationGraphAnalyzer(self.config.get('graph_analysis', {}))
        
        # Database for storing profiles and results
        self.db_path = "/var/lib/nsm/behavioral_analysis.db"
        self._init_database()
        
        # Entity profiles cache
        self.entity_profiles: Dict[str, EntityProfile] = {}
        self.peer_groups: Dict[str, List[str]] = {}
        
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from YAML file"""
        try:
            with open(self.config_path, 'r') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            logger.warning(f"Config file {self.config_path} not found, using defaults")
            return self._default_config()
    
    def _default_config(self) -> Dict[str, Any]:
        """Return default configuration"""
        return {
            'profiler': {
                'min_activity_threshold': 50,
                'profile_window_days': 30
            },
            'peer_groups': {
                'min_group_size': 5,
                'max_group_size': 50,
                'similarity_threshold': 0.8
            },
            'graph_analysis': {
                'enable_community_detection': True,
                'enable_centrality_analysis': True
            },
            'anomaly_detection': {
                'peer_deviation_threshold': 2.0,
                'risk_increase_threshold': 0.3
            }
        }
    
    def _init_database(self):
        """Initialize database for storing behavioral analysis results"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS entity_profiles (
                    entity_id TEXT PRIMARY KEY,
                    entity_type TEXT,
                    profile_data TEXT,
                    behavioral_vector TEXT,
                    risk_score REAL,
                    anomaly_score REAL,
                    peer_group TEXT,
                    last_updated TIMESTAMP,
                    confidence REAL
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS behavioral_anomalies (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    entity_id TEXT,
                    entity_type TEXT,
                    anomaly_type TEXT,
                    timestamp TIMESTAMP,
                    description TEXT,
                    severity TEXT,
                    confidence REAL,
                    risk_increase REAL,
                    baseline_deviation REAL,
                    context TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS peer_groups (
                    group_id TEXT PRIMARY KEY,
                    entity_type TEXT,
                    members TEXT,
                    created_at TIMESTAMP,
                    last_updated TIMESTAMP
                )
            """)
            
            # Create indexes
            conn.execute("CREATE INDEX IF NOT EXISTS idx_profiles_entity_type ON entity_profiles(entity_type)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_anomalies_entity ON behavioral_anomalies(entity_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_anomalies_timestamp ON behavioral_anomalies(timestamp)")
    
    async def analyze_entity_behavior(self, entity_id: str, entity_type: str, 
                                    activities: List[Dict[str, Any]]) -> EntityProfile:
        """Analyze behavior for a specific entity"""
        logger.info(f"Analyzing behavior for {entity_type} entity: {entity_id}")
        
        # Create behavioral profile
        if entity_type == 'user':
            profile = self.profiler.profile_user_behavior(entity_id, activities)
        elif entity_type == 'host':
            profile = self.profiler.profile_host_behavior(entity_id, activities)
        else:
            logger.warning(f"Unsupported entity type: {entity_type}")
            return self.profiler._create_minimal_profile(entity_id, entity_type)
        
        # Store profile
        self.entity_profiles[entity_id] = profile
        await self._store_entity_profile(profile)
        
        # Detect behavioral anomalies
        anomalies = await self._detect_behavioral_anomalies(profile)
        
        # Store anomalies
        for anomaly in anomalies:
            await self._store_behavioral_anomaly(anomaly)
        
        return profile
    
    async def update_peer_groups(self, entity_type: str = None):
        """Update peer groups for entities"""
        logger.info(f"Updating peer groups for entity type: {entity_type or 'all'}")
        
        # Get profiles to analyze
        profiles_to_analyze = []
        for profile in self.entity_profiles.values():
            if entity_type is None or profile.entity_type == entity_type:
                if profile.confidence > 0.3 and profile.behavioral_vector:
                    profiles_to_analyze.append(profile)
        
        if len(profiles_to_analyze) < 5:
            logger.warning("Insufficient profiles for peer group analysis")
            return
        
        # Create peer groups
        new_peer_groups = self.peer_analyzer.create_peer_groups(profiles_to_analyze)
        
        # Update peer group assignments
        for group_name, member_ids in new_peer_groups.items():
            for member_id in member_ids:
                if member_id in self.entity_profiles:
                    self.entity_profiles[member_id].peer_group = group_name
        
        # Store peer groups
        self.peer_groups.update(new_peer_groups)
        await self._store_peer_groups(new_peer_groups, entity_type or 'mixed')
        
        logger.info(f"Created {len(new_peer_groups)} peer groups")
    
    async def analyze_communication_graph(self, flows: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze communication patterns using graph analysis"""
        logger.info("Analyzing communication graph")
        
        # Build communication graph
        graph = self.graph_analyzer.build_communication_graph(flows)
        
        # Analyze patterns
        analysis = self.graph_analyzer.analyze_communication_patterns()
        
        return analysis
    
    async def _detect_behavioral_anomalies(self, profile: EntityProfile) -> List[BehavioralAnomaly]:
        """Detect behavioral anomalies for an entity"""
        anomalies = []
        
        # Compare to peer group if available
        if profile.peer_group and profile.peer_group in self.peer_groups:
            peer_member_ids = self.peer_groups[profile.peer_group]
            peer_profiles = [self.entity_profiles[pid] for pid in peer_member_ids 
                           if pid in self.entity_profiles and pid != profile.entity_id]
            
            if peer_profiles:
                peer_comparison = self.peer_analyzer.compare_to_peer_group(profile, peer_profiles)
                
                # Check for significant deviations
                deviation_threshold = self.config.get('anomaly_detection', {}).get('peer_deviation_threshold', 2.0)
                if peer_comparison.get('deviation_score', 0) > deviation_threshold:
                    anomaly = BehavioralAnomaly(
                        entity_id=profile.entity_id,
                        entity_type=profile.entity_type,
                        anomaly_type='peer_group_deviation',
                        timestamp=datetime.now(),
                        description=f"Behavior significantly deviates from peer group (deviation score: {peer_comparison.get('deviation_score', 0):.2f})",
                        severity=self._determine_anomaly_severity(peer_comparison.get('deviation_score', 0)),
                        confidence=min(0.9, peer_comparison.get('deviation_score', 0) / 5.0),
                        risk_increase=min(0.5, peer_comparison.get('deviation_score', 0) / 10.0),
                        baseline_deviation=peer_comparison.get('deviation_score', 0),
                        peer_comparison=peer_comparison
                    )
                    anomalies.append(anomaly)
        
        # Check for high risk indicators
        if profile.risk_indicators:
            for indicator in profile.risk_indicators:
                anomaly = BehavioralAnomaly(
                    entity_id=profile.entity_id,
                    entity_type=profile.entity_type,
                    anomaly_type='risk_indicator',
                    timestamp=datetime.now(),
                    description=f"Risk indicator detected: {indicator}",
                    severity='medium',
                    confidence=0.7,
                    risk_increase=0.2,
                    baseline_deviation=1.0,
                    affected_patterns=[indicator]
                )
                anomalies.append(anomaly)
        
        # Check for significant risk score increase
        risk_threshold = self.config.get('anomaly_detection', {}).get('risk_increase_threshold', 0.3)
        if profile.risk_score > 0.7:
            anomaly = BehavioralAnomaly(
                entity_id=profile.entity_id,
                entity_type=profile.entity_type,
                anomaly_type='high_risk_score',
                timestamp=datetime.now(),
                description=f"High risk score detected: {profile.risk_score:.2f}",
                severity=self._determine_risk_severity(profile.risk_score),
                confidence=profile.confidence,
                risk_increase=profile.risk_score - 0.5,  # Baseline risk
                baseline_deviation=profile.risk_score * 2
            )
            anomalies.append(anomaly)
        
        return anomalies
    
    def _determine_anomaly_severity(self, deviation_score: float) -> str:
        """Determine anomaly severity based on deviation score"""
        if deviation_score >= 4.0:
            return 'critical'
        elif deviation_score >= 3.0:
            return 'high'
        elif deviation_score >= 2.0:
            return 'medium'
        else:
            return 'low'
    
    def _determine_risk_severity(self, risk_score: float) -> str:
        """Determine severity based on risk score"""
        if risk_score >= 0.9:
            return 'critical'
        elif risk_score >= 0.7:
            return 'high'
        elif risk_score >= 0.5:
            return 'medium'
        else:
            return 'low'
    
    async def _store_entity_profile(self, profile: EntityProfile):
        """Store entity profile in database"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO entity_profiles 
                (entity_id, entity_type, profile_data, behavioral_vector, risk_score, 
                 anomaly_score, peer_group, last_updated, confidence)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                profile.entity_id,
                profile.entity_type,
                json.dumps(profile.profile_data, default=str),
                json.dumps(profile.behavioral_vector),
                profile.risk_score,
                profile.anomaly_score,
                profile.peer_group,
                profile.last_updated,
                profile.confidence
            ))
    
    async def _store_behavioral_anomaly(self, anomaly: BehavioralAnomaly):
        """Store behavioral anomaly in database"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO behavioral_anomalies 
                (entity_id, entity_type, anomaly_type, timestamp, description, 
                 severity, confidence, risk_increase, baseline_deviation, context)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                anomaly.entity_id,
                anomaly.entity_type,
                anomaly.anomaly_type,
                anomaly.timestamp,
                anomaly.description,
                anomaly.severity,
                anomaly.confidence,
                anomaly.risk_increase,
                anomaly.baseline_deviation,
                json.dumps({
                    'affected_patterns': anomaly.affected_patterns,
                    'peer_comparison': anomaly.peer_comparison,
                    'historical_context': anomaly.historical_context,
                    'recommendations': anomaly.recommendations
                }, default=str)
            ))
    
    async def _store_peer_groups(self, peer_groups: Dict[str, List[str]], entity_type: str):
        """Store peer groups in database"""
        with sqlite3.connect(self.db_path) as conn:
            current_time = datetime.now()
            
            for group_id, members in peer_groups.items():
                conn.execute("""
                    INSERT OR REPLACE INTO peer_groups 
                    (group_id, entity_type, members, created_at, last_updated)
                    VALUES (?, ?, ?, ?, ?)
                """, (
                    group_id,
                    entity_type,
                    json.dumps(members),
                    current_time,
                    current_time
                ))

async def main():
    """Main function for behavioral pattern analyzer"""
    analyzer = BehavioralPatternAnalyzer()
    
    # Example usage
    logger.info("Starting behavioral pattern analysis example")
    
    # Simulate user activities
    user_activities = []
    for i in range(200):
        activity = {
            'timestamp': datetime.now() - timedelta(hours=i),
            'resource': f'file_{i % 10}.txt',
            'host': f'server_{i % 5}.local',
            'application': f'app_{i % 3}',
            'action': 'read' if i % 3 == 0 else 'write',
            'data_size': np.random.normal(1000, 200)
        }
        user_activities.append(activity)
    
    # Analyze user behavior
    user_profile = await analyzer.analyze_entity_behavior('user123', 'user', user_activities)
    logger.info(f"User profile created with risk score: {user_profile.risk_score:.2f}")
    
    # Simulate network flows for host analysis
    host_flows = []
    for i in range(500):
        flow = {
            'timestamp': datetime.now() - timedelta(minutes=i),
            'source_ip': '192.168.1.100',
            'destination_ip': f'192.168.1.{(i % 50) + 1}',
            'destination_port': [80, 443, 22, 3389, 1433][i % 5],
            'protocol': ['tcp', 'udp'][i % 2],
            'bytes_sent': np.random.normal(5000, 1000),
            'bytes_received': np.random.normal(3000, 500),
            'application': ['http', 'https', 'ssh', 'rdp', 'sql'][i % 5]
        }
        host_flows.append(flow)
    
    # Analyze host behavior
    host_profile = await analyzer.analyze_entity_behavior('host_192.168.1.100', 'host', host_flows)
    logger.info(f"Host profile created with risk score: {host_profile.risk_score:.2f}")
    
    # Analyze communication graph
    graph_analysis = await analyzer.analyze_communication_graph(host_flows)
    logger.info(f"Communication graph analysis completed: {len(graph_analysis)} metrics")

if __name__ == "__main__":
    asyncio.run(main())