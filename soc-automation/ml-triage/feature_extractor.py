"""
Alert Feature Extractor - Advanced feature engineering for ML-based alert triage

Extracts comprehensive features from enriched alerts including temporal patterns,
network behaviors, asset context, user patterns, and threat intelligence indicators.
"""

import asyncio
import re
import json
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Tuple
from collections import Counter, defaultdict
import numpy as np
import pandas as pd
import structlog

logger = structlog.get_logger(__name__)

class AlertFeatureExtractor:
    """
    Advanced feature extractor that converts enriched security alerts
    into structured feature vectors for machine learning models.
    
    Features extracted:
    - Alert content features (severity, category, source)
    - Temporal features (time patterns, frequency)
    - Network behavior features (IPs, ports, protocols)
    - Asset context features (criticality, ownership)
    - User behavior features (risk scores, patterns)
    - Threat intelligence features (IOCs, reputation)
    - Enrichment quality features (completeness)
    - Historical pattern features (frequency, trends)
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        
        # Feature extraction configuration
        self.time_window_hours = self.config.get('time_window_hours', 24)
        self.max_categorical_values = self.config.get('max_categorical_values', 100)
        self.enable_text_features = self.config.get('enable_text_features', True)
        self.enable_network_features = self.config.get('enable_network_features', True)
        
        # Feature caching for performance
        self.feature_cache = {}
        self.cache_ttl = self.config.get('feature_cache_ttl', 300)  # 5 minutes
        
        # Precomputed lookup tables
        self.severity_mapping = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'informational': 0}
        self.priority_mapping = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'informational': 0}
        
        # Network analysis patterns
        self.private_ip_patterns = [
            re.compile(r'^10\.'),
            re.compile(r'^192\.168\.'),
            re.compile(r'^172\.(1[6-9]|2[0-9]|3[01])\.'),
            re.compile(r'^127\.'),
            re.compile(r'^169\.254\.'),
            re.compile(r'^::1$'),
            re.compile(r'^fc00:'),
            re.compile(r'^fe80:')
        ]
        
        # Threat category patterns
        self.threat_patterns = {
            'malware': [r'malware', r'virus', r'trojan', r'ransomware', r'rootkit'],
            'network_attack': [r'intrusion', r'scan', r'brute.*force', r'ddos'],
            'data_exfiltration': [r'exfiltration', r'data.*theft', r'unauthorized.*transfer'],
            'privilege_escalation': [r'privilege.*escalation', r'elevation', r'admin.*access'],
            'lateral_movement': [r'lateral.*movement', r'remote.*execution', r'pass.*the.*hash'],
            'persistence': [r'persistence', r'backdoor', r'scheduled.*task', r'startup']
        }
        
        logger.info("AlertFeatureExtractor initialized",
                   time_window_hours=self.time_window_hours,
                   enable_text_features=self.enable_text_features,
                   enable_network_features=self.enable_network_features)
    
    async def initialize(self):
        """Initialize feature extractor"""
        logger.info("Feature extractor initialized")
    
    async def extract_features(self, enriched_alert: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract comprehensive features from an enriched alert
        
        Args:
            enriched_alert: Alert with enrichment data
            
        Returns:
            Dictionary of extracted features
        """
        try:
            alert_id = enriched_alert.get('alert_id', 'unknown')
            
            # Check cache first
            cache_key = self._generate_cache_key(enriched_alert)
            if cache_key in self.feature_cache:
                cached_entry = self.feature_cache[cache_key]
                if datetime.now(timezone.utc) - cached_entry['timestamp'] < timedelta(seconds=self.cache_ttl):
                    logger.debug("Using cached features", alert_id=alert_id)
                    return cached_entry['features']
            
            features = {}
            
            # Extract different feature categories
            features.update(await self._extract_basic_features(enriched_alert))
            features.update(await self._extract_temporal_features(enriched_alert))
            features.update(await self._extract_content_features(enriched_alert))
            
            if self.enable_network_features:
                features.update(await self._extract_network_features(enriched_alert))
            
            if self.enable_text_features:
                features.update(await self._extract_text_features(enriched_alert))
            
            features.update(await self._extract_enrichment_features(enriched_alert))
            features.update(await self._extract_threat_intelligence_features(enriched_alert))
            features.update(await self._extract_asset_features(enriched_alert))
            features.update(await self._extract_user_features(enriched_alert))
            features.update(await self._extract_historical_features(enriched_alert))
            features.update(await self._extract_quality_features(enriched_alert))
            
            # Cache results
            self.feature_cache[cache_key] = {
                'features': features,
                'timestamp': datetime.now(timezone.utc)
            }
            
            logger.debug("Features extracted successfully",
                        alert_id=alert_id,
                        feature_count=len(features))
            
            return features
            
        except Exception as e:
            logger.error("Feature extraction failed",
                        alert_id=enriched_alert.get('alert_id'),
                        error=str(e))
            return {}  # Return empty features on failure
    
    async def _extract_basic_features(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Extract basic alert features"""
        features = {}
        
        # Severity features
        severity = alert.get('severity', 'medium').lower()
        features['severity_encoded'] = self.severity_mapping.get(severity, 2)
        features['severity_is_critical'] = 1 if severity == 'critical' else 0
        features['severity_is_high'] = 1 if severity in ['critical', 'high'] else 0
        
        # Category features
        category = alert.get('category', '').lower()
        for threat_type, patterns in self.threat_patterns.items():
            features[f'category_is_{threat_type}'] = 1 if any(re.search(pattern, category) for pattern in patterns) else 0
        
        # Source features
        source = alert.get('source', '').lower()
        features['source_is_siem'] = 1 if 'siem' in source else 0
        features['source_is_edr'] = 1 if any(edr in source for edr in ['edr', 'endpoint', 'crowdstrike', 'sentinel']) else 0
        features['source_is_network'] = 1 if any(net in source for net in ['network', 'ids', 'ips', 'suricata']) else 0
        
        # Alert type features
        alert_type = alert.get('alert_type', '').lower()
        features['alert_type_length'] = len(alert_type)
        features['alert_type_word_count'] = len(alert_type.split())
        
        return features
    
    async def _extract_temporal_features(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Extract temporal pattern features"""
        features = {}
        
        try:
            # Parse alert timestamp
            timestamp_str = alert.get('timestamp')
            if timestamp_str:
                if isinstance(timestamp_str, str):
                    timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                else:
                    timestamp = timestamp_str
            else:
                timestamp = datetime.now(timezone.utc)
            
            # Time-based features
            features['hour_of_day'] = timestamp.hour
            features['day_of_week'] = timestamp.weekday()
            features['is_weekend'] = 1 if timestamp.weekday() >= 5 else 0
            features['is_business_hours'] = 1 if 9 <= timestamp.hour <= 17 and timestamp.weekday() < 5 else 0
            features['is_after_hours'] = 1 - features['is_business_hours']
            features['is_night_time'] = 1 if timestamp.hour < 6 or timestamp.hour > 22 else 0
            
            # Seasonal features
            features['month'] = timestamp.month
            features['quarter'] = (timestamp.month - 1) // 3 + 1
            features['day_of_month'] = timestamp.day
            features['week_of_year'] = timestamp.isocalendar()[1]
            
            # Time since features (if metadata available)
            metadata = alert.get('metadata', {})
            if 'ingestion_time' in metadata:
                ingestion_time = datetime.fromisoformat(metadata['ingestion_time'].replace('Z', '+00:00'))
                features['time_to_ingestion_seconds'] = (ingestion_time - timestamp).total_seconds()
            
            # Processing time features
            if 'processing_time_ms' in alert:
                features['processing_time_ms'] = alert['processing_time_ms']
                features['processing_time_slow'] = 1 if alert['processing_time_ms'] > 1000 else 0
            
        except Exception as e:
            logger.warning("Temporal feature extraction failed", error=str(e))
            # Provide default values
            features.update({
                'hour_of_day': 12, 'day_of_week': 2, 'is_weekend': 0,
                'is_business_hours': 1, 'is_after_hours': 0, 'is_night_time': 0
            })
        
        return features
    
    async def _extract_content_features(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Extract features from alert content"""
        features = {}
        
        # Description and details features
        description = alert.get('description', '')
        features['description_length'] = len(description)
        features['description_word_count'] = len(description.split()) if description else 0
        features['has_description'] = 1 if description else 0
        
        # Details analysis
        details = alert.get('details', {})
        if isinstance(details, dict):
            features['details_field_count'] = len(details)
            features['details_has_nested'] = 1 if any(isinstance(v, dict) for v in details.values()) else 0
        else:
            features['details_field_count'] = 0
            features['details_has_nested'] = 0
        
        # Signature features
        signature = alert.get('signature', '')
        features['signature_length'] = len(signature)
        features['signature_word_count'] = len(signature.split()) if signature else 0
        features['has_signature'] = 1 if signature else 0
        
        # Rule ID features
        rule_id = alert.get('rule_id')
        features['has_rule_id'] = 1 if rule_id else 0
        
        # MITRE ATT&CK features
        mitre_tactics = alert.get('mitre_tactics', [])
        mitre_techniques = alert.get('mitre_techniques', [])
        features['mitre_tactic_count'] = len(mitre_tactics)
        features['mitre_technique_count'] = len(mitre_techniques)
        features['has_mitre_mapping'] = 1 if (mitre_tactics or mitre_techniques) else 0
        
        # Tag features
        tags = alert.get('tags', [])
        features['tag_count'] = len(tags) if isinstance(tags, list) else 0
        features['has_tags'] = 1 if tags else 0
        
        # Common tag analysis
        if isinstance(tags, list):
            tag_text = ' '.join(tags).lower()
            features['tags_has_malicious'] = 1 if 'malicious' in tag_text else 0
            features['tags_has_suspicious'] = 1 if 'suspicious' in tag_text else 0
            features['tags_has_external'] = 1 if 'external' in tag_text else 0
            features['tags_has_internal'] = 1 if 'internal' in tag_text else 0
        
        return features
    
    async def _extract_network_features(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Extract network-related features"""
        features = {}
        
        # IP address features
        source_ip = alert.get('source_ip')
        dest_ip = alert.get('destination_ip')
        
        if source_ip:
            features['has_source_ip'] = 1
            features['source_ip_is_private'] = 1 if self._is_private_ip(source_ip) else 0
            features['source_ip_is_external'] = 1 - features['source_ip_is_private']
        else:
            features['has_source_ip'] = 0
            features['source_ip_is_private'] = 0
            features['source_ip_is_external'] = 0
        
        if dest_ip:
            features['has_dest_ip'] = 1
            features['dest_ip_is_private'] = 1 if self._is_private_ip(dest_ip) else 0
            features['dest_ip_is_external'] = 1 - features['dest_ip_is_private']
        else:
            features['has_dest_ip'] = 0
            features['dest_ip_is_private'] = 0
            features['dest_ip_is_external'] = 0
        
        # Port features
        source_port = alert.get('source_port')
        dest_port = alert.get('destination_port')
        
        features['has_source_port'] = 1 if source_port else 0
        features['has_dest_port'] = 1 if dest_port else 0
        
        if source_port:
            features['source_port_is_privileged'] = 1 if source_port < 1024 else 0
            features['source_port_is_ephemeral'] = 1 if source_port > 32768 else 0
        
        if dest_port:
            features['dest_port_is_privileged'] = 1 if dest_port < 1024 else 0
            features['dest_port_is_common'] = 1 if dest_port in [80, 443, 22, 21, 25, 53, 110, 143, 993, 995] else 0
        
        # Protocol features
        protocol = alert.get('protocol', '').lower()
        features['has_protocol'] = 1 if protocol else 0
        features['protocol_is_tcp'] = 1 if protocol == 'tcp' else 0
        features['protocol_is_udp'] = 1 if protocol == 'udp' else 0
        features['protocol_is_icmp'] = 1 if protocol == 'icmp' else 0
        
        # Network direction analysis
        if source_ip and dest_ip:
            source_is_private = self._is_private_ip(source_ip)
            dest_is_private = self._is_private_ip(dest_ip)
            
            features['traffic_is_inbound'] = 1 if not source_is_private and dest_is_private else 0
            features['traffic_is_outbound'] = 1 if source_is_private and not dest_is_private else 0
            features['traffic_is_internal'] = 1 if source_is_private and dest_is_private else 0
            features['traffic_is_external'] = 1 if not source_is_private and not dest_is_private else 0
        
        return features
    
    async def _extract_text_features(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Extract features from text content using NLP techniques"""
        features = {}
        
        try:
            # Combine all text fields
            text_fields = [
                alert.get('description', ''),
                alert.get('signature', ''),
                alert.get('alert_type', ''),
                str(alert.get('details', ''))
            ]
            
            combined_text = ' '.join(text_fields).lower()
            
            # Text statistics
            features['total_text_length'] = len(combined_text)
            features['total_word_count'] = len(combined_text.split())
            features['unique_word_count'] = len(set(combined_text.split()))
            features['avg_word_length'] = np.mean([len(word) for word in combined_text.split()]) if combined_text.split() else 0
            
            # Keyword presence (security-relevant terms)
            security_keywords = [
                'malware', 'virus', 'trojan', 'ransomware', 'backdoor',
                'attack', 'intrusion', 'breach', 'compromise', 'exploit',
                'suspicious', 'anomaly', 'threat', 'malicious', 'unauthorized',
                'scan', 'brute', 'force', 'injection', 'overflow',
                'phishing', 'spam', 'botnet', 'c2', 'command', 'control'
            ]
            
            for keyword in security_keywords:
                features[f'text_has_{keyword}'] = 1 if keyword in combined_text else 0
            
            # Count security keywords
            features['security_keyword_count'] = sum(1 for keyword in security_keywords if keyword in combined_text)
            
            # Special character analysis
            features['text_has_urls'] = 1 if re.search(r'http[s]?://', combined_text) else 0
            features['text_has_ips'] = 1 if re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', combined_text) else 0
            features['text_has_domains'] = 1 if re.search(r'\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b', combined_text) else 0
            features['text_has_file_paths'] = 1 if re.search(r'[/\\][a-zA-Z0-9_.-]+', combined_text) else 0
            features['text_has_hashes'] = 1 if re.search(r'\b[a-fA-F0-9]{32,64}\b', combined_text) else 0
            
            # Sentiment/urgency indicators
            urgent_words = ['critical', 'urgent', 'immediate', 'emergency', 'severe', 'high']
            features['text_urgency_score'] = sum(1 for word in urgent_words if word in combined_text) / len(urgent_words)
            
        except Exception as e:
            logger.warning("Text feature extraction failed", error=str(e))
            features.update({
                'total_text_length': 0, 'total_word_count': 0,
                'unique_word_count': 0, 'avg_word_length': 0,
                'security_keyword_count': 0, 'text_urgency_score': 0
            })
        
        return features
    
    async def _extract_enrichment_features(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Extract features from enrichment data"""
        features = {}
        
        enrichments = alert.get('enrichments', {})
        
        # Enrichment availability
        enrichment_types = [
            'threat_intelligence_source', 'threat_intelligence_destination',
            'geolocation_source', 'geolocation_destination',
            'asn_source', 'asn_destination',
            'asset_information', 'user_context',
            'vulnerability_data', 'historical_context'
        ]
        
        for enrich_type in enrichment_types:
            features[f'has_{enrich_type}'] = 1 if enrich_type in enrichments else 0
        
        # Enrichment quality scores
        features['enrichment_count'] = len(enrichments)
        features['enrichment_coverage'] = len(enrichments) / len(enrichment_types)
        
        # Enrichment summary
        enrichment_summary = alert.get('enrichment_summary', {})
        features['total_enrichments'] = enrichment_summary.get('total_enrichments', 0)
        features['successful_enrichments'] = enrichment_summary.get('successful_enrichments', 0)
        features['failed_enrichments'] = enrichment_summary.get('failed_enrichments', 0)
        
        if features['total_enrichments'] > 0:
            features['enrichment_success_rate'] = features['successful_enrichments'] / features['total_enrichments']
        else:
            features['enrichment_success_rate'] = 0
        
        return features
    
    async def _extract_threat_intelligence_features(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Extract threat intelligence features"""
        features = {}
        
        enrichments = alert.get('enrichments', {})
        
        # Source IP threat intelligence
        source_ti = enrichments.get('threat_intelligence_source', {})
        if source_ti:
            features['source_threat_score'] = source_ti.get('reputation_score', 0) / 100.0
            features['source_is_malicious'] = 1 if source_ti.get('is_malicious') else 0
            features['source_threat_categories'] = len(source_ti.get('threat_categories', []))
        else:
            features['source_threat_score'] = 0
            features['source_is_malicious'] = 0
            features['source_threat_categories'] = 0
        
        # Destination IP threat intelligence
        dest_ti = enrichments.get('threat_intelligence_destination', {})
        if dest_ti:
            features['dest_threat_score'] = dest_ti.get('reputation_score', 0) / 100.0
            features['dest_is_malicious'] = 1 if dest_ti.get('is_malicious') else 0
            features['dest_threat_categories'] = len(dest_ti.get('threat_categories', []))
        else:
            features['dest_threat_score'] = 0
            features['dest_is_malicious'] = 0
            features['dest_threat_categories'] = 0
        
        # Overall threat score
        features['max_threat_score'] = max(features['source_threat_score'], features['dest_threat_score'])
        features['any_ip_malicious'] = max(features['source_is_malicious'], features['dest_is_malicious'])
        
        return features
    
    async def _extract_asset_features(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Extract asset context features"""
        features = {}
        
        asset_info = alert.get('enrichments', {}).get('asset_information', {})
        
        if asset_info:
            # Asset criticality
            criticality = asset_info.get('criticality', 'low').lower()
            criticality_map = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'unknown': 0}
            features['asset_criticality'] = criticality_map.get(criticality, 1) / 4.0
            features['asset_is_critical'] = 1 if criticality in ['critical', 'high'] else 0
            
            # Asset context
            features['asset_has_owner'] = 1 if asset_info.get('owner') else 0
            features['asset_has_location'] = 1 if asset_info.get('location') else 0
            
            # Business unit mapping
            business_unit = asset_info.get('business_unit', '').lower()
            critical_business_units = ['finance', 'hr', 'executive', 'security']
            features['asset_in_critical_bu'] = 1 if any(bu in business_unit for bu in critical_business_units) else 0
            
            # Compliance status
            compliance_status = asset_info.get('compliance_status', 'unknown').lower()
            features['asset_is_compliant'] = 1 if compliance_status == 'compliant' else 0
            
        else:
            features.update({
                'asset_criticality': 0.5,  # Unknown, assume medium
                'asset_is_critical': 0,
                'asset_has_owner': 0,
                'asset_has_location': 0,
                'asset_in_critical_bu': 0,
                'asset_is_compliant': 0
            })
        
        return features
    
    async def _extract_user_features(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Extract user context features"""
        features = {}
        
        user_context = alert.get('enrichments', {}).get('user_context', {})
        
        if user_context:
            # User risk score
            features['user_risk_score'] = user_context.get('risk_score', 50) / 100.0
            features['user_is_high_risk'] = 1 if user_context.get('risk_score', 50) > 70 else 0
            
            # User context availability
            features['user_has_department'] = 1 if user_context.get('department') else 0
            features['user_has_manager'] = 1 if user_context.get('manager') else 0
            
            # Privileged access
            access_privileges = user_context.get('access_privileges', [])
            if isinstance(access_privileges, list):
                privileged_roles = ['admin', 'root', 'administrator', 'power_user']
                features['user_has_privileged_access'] = 1 if any(priv in ' '.join(access_privileges).lower() for priv in privileged_roles) else 0
            else:
                features['user_has_privileged_access'] = 0
            
            # Recent activity indicators
            recent_activities = user_context.get('recent_activities', [])
            if isinstance(recent_activities, list):
                features['user_recent_activity_count'] = len(recent_activities)
                features['user_has_recent_activity'] = 1 if recent_activities else 0
            else:
                features['user_recent_activity_count'] = 0
                features['user_has_recent_activity'] = 0
            
        else:
            features.update({
                'user_risk_score': 0.5,  # Unknown, assume medium
                'user_is_high_risk': 0,
                'user_has_department': 0,
                'user_has_manager': 0,
                'user_has_privileged_access': 0,
                'user_recent_activity_count': 0,
                'user_has_recent_activity': 0
            })
        
        return features
    
    async def _extract_historical_features(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Extract historical pattern features"""
        features = {}
        
        historical_context = alert.get('enrichments', {}).get('historical_context', {})
        
        if historical_context:
            # Alert frequency
            features['similar_alerts_24h'] = historical_context.get('similar_alerts_24h', 0)
            features['similar_alerts_7d'] = historical_context.get('similar_alerts_7d', 0)
            
            # Frequency indicators
            features['is_frequent_alert'] = 1 if historical_context.get('similar_alerts_24h', 0) > 10 else 0
            features['is_rare_alert'] = 1 if historical_context.get('similar_alerts_7d', 0) <= 1 else 0
            
            # Trend analysis
            trend = historical_context.get('trend', 'stable').lower()
            features['trend_is_increasing'] = 1 if trend == 'increasing' else 0
            features['trend_is_spike'] = 1 if trend == 'spike' else 0
            
            # Frequency score
            features['frequency_score'] = min(historical_context.get('frequency_score', 0) / 10.0, 1.0)
            
            # Related incidents
            related_incidents = historical_context.get('related_incidents', [])
            features['has_related_incidents'] = 1 if related_incidents else 0
            features['related_incident_count'] = len(related_incidents) if isinstance(related_incidents, list) else 0
            
        else:
            features.update({
                'similar_alerts_24h': 0,
                'similar_alerts_7d': 0,
                'is_frequent_alert': 0,
                'is_rare_alert': 1,  # Assume rare if no historical data
                'trend_is_increasing': 0,
                'trend_is_spike': 0,
                'frequency_score': 0,
                'has_related_incidents': 0,
                'related_incident_count': 0
            })
        
        return features
    
    async def _extract_quality_features(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Extract data quality and completeness features"""
        features = {}
        
        # Core field completeness
        required_fields = ['alert_id', 'timestamp', 'source', 'severity', 'alert_type']
        optional_fields = ['description', 'signature', 'rule_id', 'hostname', 'user', 'source_ip', 'destination_ip']
        
        features['required_field_completeness'] = sum(1 for field in required_fields if alert.get(field)) / len(required_fields)
        features['optional_field_completeness'] = sum(1 for field in optional_fields if alert.get(field)) / len(optional_fields)
        features['overall_completeness'] = (features['required_field_completeness'] + features['optional_field_completeness']) / 2
        
        # Data quality indicators
        features['has_all_required_fields'] = 1 if features['required_field_completeness'] == 1.0 else 0
        features['is_high_quality'] = 1 if features['overall_completeness'] > 0.8 else 0
        
        # Processing metadata
        metadata = alert.get('metadata', {})
        if metadata:
            features['has_processing_metadata'] = 1
            features['processing_stage_count'] = 1 if metadata.get('processing_stage') else 0
            features['has_enrichment_count'] = 1 if 'enrichment_count' in metadata else 0
        else:
            features['has_processing_metadata'] = 0
            features['processing_stage_count'] = 0
            features['has_enrichment_count'] = 0
        
        # Deduplication indicators
        duplicate_info = alert.get('duplicate_info', {})
        if duplicate_info:
            features['is_duplicate'] = 1 if duplicate_info.get('is_duplicate') else 0
            features['duplicate_count'] = min(duplicate_info.get('duplicate_count', 0) / 10.0, 1.0)
        else:
            features['is_duplicate'] = 0
            features['duplicate_count'] = 0
        
        return features
    
    def _is_private_ip(self, ip_address: str) -> bool:
        """Check if IP address is in private range"""
        try:
            return any(pattern.match(ip_address) for pattern in self.private_ip_patterns)
        except Exception:
            return False
    
    def _generate_cache_key(self, alert: Dict[str, Any]) -> str:
        """Generate cache key for feature extraction"""
        # Use alert content hash as cache key
        alert_content = {
            'alert_id': alert.get('alert_id'),
            'timestamp': alert.get('timestamp'),
            'severity': alert.get('severity'),
            'category': alert.get('category'),
            'source_ip': alert.get('source_ip'),
            'destination_ip': alert.get('destination_ip'),
            'enrichment_count': len(alert.get('enrichments', {}))
        }
        
        content_str = json.dumps(alert_content, sort_keys=True)
        return hashlib.md5(content_str.encode()).hexdigest()
    
    def get_feature_statistics(self) -> Dict[str, Any]:
        """Get feature extraction statistics"""
        return {
            'cache_size': len(self.feature_cache),
            'cache_hit_rate': 0.0,  # Would track in production
            'feature_extraction_count': 0,  # Would track in production
            'average_feature_count': 0,  # Would track in production
            'config': {
                'time_window_hours': self.time_window_hours,
                'enable_text_features': self.enable_text_features,
                'enable_network_features': self.enable_network_features,
                'cache_ttl': self.cache_ttl
            }
        }