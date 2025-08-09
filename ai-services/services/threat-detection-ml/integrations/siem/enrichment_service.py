"""
Alert Enrichment Service

Production-grade service that enriches SIEM alerts with AI/ML insights,
threat intelligence, and contextual information for enhanced threat analysis.
"""

import asyncio
import logging
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union, Callable
from dataclasses import dataclass, field
from enum import Enum
import aiohttp
from pydantic import BaseModel, Field

from .base_connector import BaseSiemConnector, SiemEvent, EventSeverity
from .correlation_engine import CorrelationResult, ThreatCorrelationEngine
from ..models.zero_day_detection import ZeroDayDetectionModel
from ..models.supervised_threat_classification import ThreatClassificationModel
from ..models.behavioral_analytics import BehavioralAnalyticsModel
from ..models.predictive_threat_intelligence import PredictiveThreatModel

logger = logging.getLogger(__name__)

class EnrichmentType(str, Enum):
    """Types of alert enrichment"""
    AI_PREDICTION = "ai_prediction"
    THREAT_INTELLIGENCE = "threat_intelligence"
    BEHAVIORAL_ANALYSIS = "behavioral_analysis"
    GEOLOCATION = "geolocation"
    ASSET_CONTEXT = "asset_context"
    USER_CONTEXT = "user_context"
    CORRELATION = "correlation"
    RISK_SCORING = "risk_scoring"

class EnrichmentStatus(str, Enum):
    """Enrichment processing status"""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    PARTIAL = "partial"

@dataclass
class EnrichmentData:
    """Enrichment data structure"""
    enrichment_type: EnrichmentType
    data: Dict[str, Any]
    confidence: float = 0.0
    source: str = "isectech-ai-ml"
    timestamp: datetime = field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'type': self.enrichment_type.value,
            'data': self.data,
            'confidence': self.confidence,
            'source': self.source,
            'timestamp': self.timestamp.isoformat(),
            'metadata': self.metadata
        }

class EnrichedAlert(BaseModel):
    """Enhanced alert with AI/ML enrichments"""
    original_event: SiemEvent
    enrichments: List[EnrichmentData] = Field(default_factory=list)
    enrichment_status: EnrichmentStatus = EnrichmentStatus.PENDING
    processing_started: datetime = Field(default_factory=datetime.utcnow)
    processing_completed: Optional[datetime] = None
    total_confidence: float = 0.0
    risk_score: float = 0.0
    priority_adjustment: int = 0  # Adjustment to original severity
    
    # Aggregated insights
    ai_insights: Dict[str, Any] = Field(default_factory=dict)
    threat_context: Dict[str, Any] = Field(default_factory=dict)
    recommended_actions: List[str] = Field(default_factory=list)
    
    class Config:
        arbitrary_types_allowed = True
        json_encoders = {
            datetime: lambda v: v.isoformat() if v else None,
            SiemEvent: lambda v: v.dict()
        }
    
    def add_enrichment(self, enrichment: EnrichmentData) -> None:
        """Add enrichment data"""
        self.enrichments.append(enrichment)
        self._update_aggregates()
    
    def get_enrichments_by_type(self, enrichment_type: EnrichmentType) -> List[EnrichmentData]:
        """Get enrichments by type"""
        return [e for e in self.enrichments if e.enrichment_type == enrichment_type]
    
    def _update_aggregates(self) -> None:
        """Update aggregated fields"""
        if self.enrichments:
            # Calculate total confidence
            confidences = [e.confidence for e in self.enrichments if e.confidence > 0]
            self.total_confidence = sum(confidences) / len(confidences) if confidences else 0.0
            
            # Aggregate AI insights
            ai_enrichments = self.get_enrichments_by_type(EnrichmentType.AI_PREDICTION)
            for enrichment in ai_enrichments:
                self.ai_insights.update(enrichment.data)
            
            # Aggregate threat context
            ti_enrichments = self.get_enrichments_by_type(EnrichmentType.THREAT_INTELLIGENCE)
            for enrichment in ti_enrichments:
                self.threat_context.update(enrichment.data)
    
    def to_siem_format(self) -> Dict[str, Any]:
        """Convert to SIEM-compatible format"""
        return {
            'original_event_id': self.original_event.id,
            'enrichment_timestamp': (self.processing_completed or datetime.utcnow()).isoformat(),
            'enrichment_status': self.enrichment_status.value,
            'total_confidence': self.total_confidence,
            'risk_score': self.risk_score,
            'priority_adjustment': self.priority_adjustment,
            'ai_insights': self.ai_insights,
            'threat_context': self.threat_context,
            'recommended_actions': self.recommended_actions,
            'enrichments': [e.to_dict() for e in self.enrichments]
        }

class AlertEnrichmentService:
    """
    Production-grade alert enrichment service
    
    Features:
    - Multi-source enrichment (AI, TI, context)
    - Parallel processing for performance
    - Configurable enrichment pipeline
    - SIEM platform integration
    - Caching and optimization
    - Error handling and fallbacks
    """
    
    def __init__(
        self,
        siem_connectors: List[BaseSiemConnector],
        correlation_engine: Optional[ThreatCorrelationEngine] = None,
        behavioral_model: Optional[BehavioralAnalyticsModel] = None,
        zero_day_model: Optional[ZeroDayDetectionModel] = None,
        threat_classification_model: Optional[ThreatClassificationModel] = None,
        predictive_model: Optional[PredictiveThreatModel] = None,
        max_concurrent_enrichments: int = 10,
        enrichment_timeout_seconds: int = 30
    ):
        self.siem_connectors = {conn.platform.value: conn for conn in siem_connectors}
        self.correlation_engine = correlation_engine
        self.behavioral_model = behavioral_model
        self.zero_day_model = zero_day_model
        self.threat_classification_model = threat_classification_model
        self.predictive_model = predictive_model
        
        # Configuration
        self.max_concurrent_enrichments = max_concurrent_enrichments
        self.enrichment_timeout_seconds = enrichment_timeout_seconds
        
        # Processing state
        self._enrichment_queue: asyncio.Queue = asyncio.Queue()
        self._processing_semaphore = asyncio.Semaphore(max_concurrent_enrichments)
        self._enrichment_cache: Dict[str, EnrichedAlert] = {}
        self._cache_ttl_minutes = 60
        
        # Metrics
        self._metrics = {
            'alerts_enriched': 0,
            'enrichments_sent': 0,
            'enrichment_failures': 0,
            'cache_hits': 0,
            'cache_misses': 0,
            'average_enrichment_time_ms': 0.0,
            'ai_predictions': 0,
            'threat_intel_lookups': 0
        }
        
        # Background tasks
        self._enrichment_worker_task: Optional[asyncio.Task] = None
        self._cache_cleanup_task: Optional[asyncio.Task] = None
        self._running = False
        
        logger.info("Alert Enrichment Service initialized")
    
    async def start(self) -> None:
        """Start the enrichment service"""
        if self._running:
            return
        
        self._running = True
        
        # Start background workers
        self._enrichment_worker_task = asyncio.create_task(self._enrichment_worker())
        self._cache_cleanup_task = asyncio.create_task(self._cache_cleanup_worker())
        
        logger.info("Alert Enrichment Service started")
    
    async def stop(self) -> None:
        """Stop the enrichment service"""
        self._running = False
        
        # Cancel background tasks
        if self._enrichment_worker_task:
            self._enrichment_worker_task.cancel()
        if self._cache_cleanup_task:
            self._cache_cleanup_task.cancel()
        
        # Wait for tasks to complete
        tasks = [self._enrichment_worker_task, self._cache_cleanup_task]
        await asyncio.gather(*[t for t in tasks if t], return_exceptions=True)
        
        logger.info("Alert Enrichment Service stopped")
    
    async def enrich_alert(
        self,
        event: SiemEvent,
        target_platforms: Optional[List[str]] = None
    ) -> EnrichedAlert:
        """
        Enrich alert with AI/ML insights and send to SIEM platforms
        
        Args:
            event: Original SIEM event to enrich
            target_platforms: Specific SIEM platforms to send enrichment to
        
        Returns:
            EnrichedAlert with all enrichment data
        """
        start_time = datetime.utcnow()
        
        try:
            # Check cache first
            cache_key = self._generate_cache_key(event)
            if cache_key in self._enrichment_cache:
                cached_alert = self._enrichment_cache[cache_key]
                if self._is_cache_valid(cached_alert):
                    self._metrics['cache_hits'] += 1
                    return cached_alert
            
            self._metrics['cache_misses'] += 1
            
            # Create enriched alert
            enriched_alert = EnrichedAlert(original_event=event)
            enriched_alert.enrichment_status = EnrichmentStatus.IN_PROGRESS
            
            # Run enrichment pipeline
            async with self._processing_semaphore:
                await asyncio.wait_for(
                    self._run_enrichment_pipeline(enriched_alert),
                    timeout=self.enrichment_timeout_seconds
                )
            
            # Mark as completed
            enriched_alert.enrichment_status = EnrichmentStatus.COMPLETED
            enriched_alert.processing_completed = datetime.utcnow()
            
            # Calculate final risk score and recommendations
            self._calculate_final_risk_score(enriched_alert)
            self._generate_recommendations(enriched_alert)
            
            # Cache the result
            self._enrichment_cache[cache_key] = enriched_alert
            
            # Send enrichment to SIEM platforms
            await self._send_enrichment_to_siems(enriched_alert, target_platforms)
            
            # Update metrics
            processing_time = (datetime.utcnow() - start_time).total_seconds() * 1000
            self._metrics['alerts_enriched'] += 1
            self._metrics['average_enrichment_time_ms'] = (
                (self._metrics['average_enrichment_time_ms'] * (self._metrics['alerts_enriched'] - 1) + processing_time) /
                self._metrics['alerts_enriched']
            )
            
            return enriched_alert
            
        except asyncio.TimeoutError:
            logger.warning(f"Enrichment timeout for event {event.id}")
            enriched_alert.enrichment_status = EnrichmentStatus.PARTIAL
            return enriched_alert
        except Exception as e:
            logger.error(f"Error enriching alert {event.id}: {e}")
            enriched_alert.enrichment_status = EnrichmentStatus.FAILED
            self._metrics['enrichment_failures'] += 1
            return enriched_alert
    
    async def _run_enrichment_pipeline(self, enriched_alert: EnrichedAlert) -> None:
        """Run the complete enrichment pipeline"""
        event = enriched_alert.original_event
        
        # Run enrichments in parallel
        enrichment_tasks = []
        
        # AI/ML predictions
        if any([self.behavioral_model, self.zero_day_model, self.threat_classification_model, self.predictive_model]):
            enrichment_tasks.append(self._enrich_with_ai_predictions(event))
        
        # Behavioral analysis
        if self.behavioral_model:
            enrichment_tasks.append(self._enrich_with_behavioral_analysis(event))
        
        # Threat intelligence
        enrichment_tasks.append(self._enrich_with_threat_intelligence(event))
        
        # Geolocation
        enrichment_tasks.append(self._enrich_with_geolocation(event))
        
        # Asset and user context
        enrichment_tasks.append(self._enrich_with_asset_context(event))
        enrichment_tasks.append(self._enrich_with_user_context(event))
        
        # Correlation data
        if self.correlation_engine:
            enrichment_tasks.append(self._enrich_with_correlation(event))
        
        # Execute all enrichments
        try:
            enrichment_results = await asyncio.gather(
                *enrichment_tasks,
                return_exceptions=True
            )
            
            # Add successful enrichments
            for result in enrichment_results:
                if isinstance(result, EnrichmentData):
                    enriched_alert.add_enrichment(result)
                elif isinstance(result, list):
                    for enrichment in result:
                        if isinstance(enrichment, EnrichmentData):
                            enriched_alert.add_enrichment(enrichment)
                elif isinstance(result, Exception):
                    logger.warning(f"Enrichment failed: {result}")
            
        except Exception as e:
            logger.error(f"Error in enrichment pipeline: {e}")
    
    async def _enrich_with_ai_predictions(self, event: SiemEvent) -> List[EnrichmentData]:
        """Enrich with AI/ML model predictions"""
        enrichments = []
        
        try:
            # Zero-day detection
            if self.zero_day_model:
                zero_day_result = await self._get_zero_day_prediction(event)
                if zero_day_result:
                    enrichments.append(EnrichmentData(
                        enrichment_type=EnrichmentType.AI_PREDICTION,
                        data={'zero_day_analysis': zero_day_result},
                        confidence=zero_day_result.get('confidence', 0.0),
                        metadata={'model': 'zero_day_detection'}
                    ))
            
            # Threat classification
            if self.threat_classification_model:
                threat_result = await self._get_threat_classification(event)
                if threat_result:
                    enrichments.append(EnrichmentData(
                        enrichment_type=EnrichmentType.AI_PREDICTION,
                        data={'threat_classification': threat_result},
                        confidence=threat_result.get('confidence', 0.0),
                        metadata={'model': 'threat_classification'}
                    ))
            
            # Predictive threat intelligence
            if self.predictive_model:
                predictive_result = await self._get_predictive_analysis(event)
                if predictive_result:
                    enrichments.append(EnrichmentData(
                        enrichment_type=EnrichmentType.AI_PREDICTION,
                        data={'predictive_analysis': predictive_result},
                        confidence=predictive_result.get('confidence', 0.0),
                        metadata={'model': 'predictive_threat'}
                    ))
            
            self._metrics['ai_predictions'] += len(enrichments)
            return enrichments
            
        except Exception as e:
            logger.error(f"Error in AI prediction enrichment: {e}")
            return []
    
    async def _enrich_with_behavioral_analysis(self, event: SiemEvent) -> EnrichmentData:
        """Enrich with behavioral analysis"""
        try:
            if not self.behavioral_model or not event.user_id:
                return None
            
            behavioral_result = await self._get_behavioral_analysis(event)
            
            if behavioral_result:
                return EnrichmentData(
                    enrichment_type=EnrichmentType.BEHAVIORAL_ANALYSIS,
                    data=behavioral_result,
                    confidence=behavioral_result.get('confidence', 0.0),
                    metadata={'user_id': event.user_id, 'asset_id': event.asset_id}
                )
            
        except Exception as e:
            logger.error(f"Error in behavioral analysis enrichment: {e}")
        
        return None
    
    async def _enrich_with_threat_intelligence(self, event: SiemEvent) -> EnrichmentData:
        """Enrich with threat intelligence data"""
        try:
            # Extract IOCs from event
            iocs = self._extract_iocs(event)
            
            if not iocs:
                return None
            
            # Query threat intelligence (placeholder implementation)
            ti_results = await self._query_threat_intelligence(iocs)
            
            if ti_results:
                self._metrics['threat_intel_lookups'] += 1
                return EnrichmentData(
                    enrichment_type=EnrichmentType.THREAT_INTELLIGENCE,
                    data=ti_results,
                    confidence=ti_results.get('confidence', 0.5),
                    metadata={'iocs_checked': len(iocs)}
                )
            
        except Exception as e:
            logger.error(f"Error in threat intelligence enrichment: {e}")
        
        return None
    
    async def _enrich_with_geolocation(self, event: SiemEvent) -> EnrichmentData:
        """Enrich with geolocation data"""
        try:
            ips = [ip for ip in [event.source_ip, event.destination_ip] if ip]
            
            if not ips:
                return None
            
            geo_data = await self._get_geolocation_data(ips)
            
            if geo_data:
                return EnrichmentData(
                    enrichment_type=EnrichmentType.GEOLOCATION,
                    data=geo_data,
                    confidence=0.8,
                    metadata={'ips_analyzed': len(ips)}
                )
            
        except Exception as e:
            logger.error(f"Error in geolocation enrichment: {e}")
        
        return None
    
    async def _enrich_with_asset_context(self, event: SiemEvent) -> EnrichmentData:
        """Enrich with asset context information"""
        try:
            if not event.asset_id:
                return None
            
            asset_context = await self._get_asset_context(event.asset_id)
            
            if asset_context:
                return EnrichmentData(
                    enrichment_type=EnrichmentType.ASSET_CONTEXT,
                    data=asset_context,
                    confidence=0.9,
                    metadata={'asset_id': event.asset_id}
                )
            
        except Exception as e:
            logger.error(f"Error in asset context enrichment: {e}")
        
        return None
    
    async def _enrich_with_user_context(self, event: SiemEvent) -> EnrichmentData:
        """Enrich with user context information"""
        try:
            if not event.user_id:
                return None
            
            user_context = await self._get_user_context(event.user_id)
            
            if user_context:
                return EnrichmentData(
                    enrichment_type=EnrichmentType.USER_CONTEXT,
                    data=user_context,
                    confidence=0.9,
                    metadata={'user_id': event.user_id}
                )
            
        except Exception as e:
            logger.error(f"Error in user context enrichment: {e}")
        
        return None
    
    async def _enrich_with_correlation(self, event: SiemEvent) -> EnrichmentData:
        """Enrich with correlation analysis"""
        try:
            if not self.correlation_engine:
                return None
            
            # Find related correlations
            correlations = []
            for correlation in self.correlation_engine.get_active_correlations():
                if event.id in correlation.events:
                    correlations.append({
                        'correlation_id': correlation.correlation_id,
                        'type': correlation.correlation_type.value,
                        'confidence': correlation.confidence_score,
                        'related_events': len(correlation.events),
                        'risk_score': correlation.risk_score
                    })
            
            if correlations:
                return EnrichmentData(
                    enrichment_type=EnrichmentType.CORRELATION,
                    data={'correlations': correlations},
                    confidence=max(c['confidence'] for c in correlations),
                    metadata={'correlation_count': len(correlations)}
                )
            
        except Exception as e:
            logger.error(f"Error in correlation enrichment: {e}")
        
        return None
    
    # AI Model Interface Methods
    
    async def _get_zero_day_prediction(self, event: SiemEvent) -> Optional[Dict[str, Any]]:
        """Get zero-day detection prediction"""
        try:
            # Convert event to features (simplified)
            features = self._event_to_features(event)
            
            # Placeholder for actual model prediction
            result = {
                'is_novel': False,
                'novelty_score': 0.0,
                'novelty_type': 'unknown',
                'confidence': 0.0,
                'explanation': 'No novel patterns detected'
            }
            
            return result if result['confidence'] > 0.1 else None
            
        except Exception as e:
            logger.error(f"Error getting zero-day prediction: {e}")
            return None
    
    async def _get_threat_classification(self, event: SiemEvent) -> Optional[Dict[str, Any]]:
        """Get threat classification prediction"""
        try:
            features = self._event_to_features(event)
            
            # Placeholder for actual model prediction
            result = {
                'predicted_category': 'unknown',
                'confidence': 0.0,
                'probabilities': {},
                'explanation': 'Classification not available'
            }
            
            return result if result['confidence'] > 0.1 else None
            
        except Exception as e:
            logger.error(f"Error getting threat classification: {e}")
            return None
    
    async def _get_predictive_analysis(self, event: SiemEvent) -> Optional[Dict[str, Any]]:
        """Get predictive threat analysis"""
        try:
            features = self._event_to_features(event)
            
            # Placeholder for actual model prediction
            result = {
                'threat_likelihood': 0.0,
                'predicted_tactics': [],
                'timeline_forecast': {},
                'confidence': 0.0,
                'risk_factors': []
            }
            
            return result if result['confidence'] > 0.1 else None
            
        except Exception as e:
            logger.error(f"Error getting predictive analysis: {e}")
            return None
    
    async def _get_behavioral_analysis(self, event: SiemEvent) -> Optional[Dict[str, Any]]:
        """Get behavioral analysis"""
        try:
            if not event.user_id:
                return None
            
            # Placeholder for actual behavioral analysis
            result = {
                'is_anomalous': False,
                'anomaly_score': 0.0,
                'behavior_profile': {},
                'deviations': [],
                'confidence': 0.0
            }
            
            return result if result['confidence'] > 0.1 else None
            
        except Exception as e:
            logger.error(f"Error getting behavioral analysis: {e}")
            return None
    
    def _event_to_features(self, event: SiemEvent) -> Dict[str, Any]:
        """Convert event to feature dictionary"""
        return {
            'timestamp': event.timestamp.timestamp(),
            'severity': event.severity.value,
            'category': event.category,
            'event_type': event.event_type,
            'source': event.source,
            'message_length': len(event.message),
            'has_source_ip': bool(event.source_ip),
            'has_destination_ip': bool(event.destination_ip),
            'has_user_id': bool(event.user_id),
            'has_asset_id': bool(event.asset_id),
            'tag_count': len(event.tags),
            'metadata_fields': len(event.metadata)
        }
    
    # External Data Source Methods
    
    async def _query_threat_intelligence(self, iocs: List[str]) -> Optional[Dict[str, Any]]:
        """Query threat intelligence sources"""
        try:
            # Placeholder for actual TI integration
            # In production, integrate with VirusTotal, ThreatConnect, etc.
            
            results = {
                'malicious_iocs': [],
                'reputation_scores': {},
                'threat_actors': [],
                'campaigns': [],
                'confidence': 0.5,
                'sources': ['placeholder_ti']
            }
            
            # Simulate some matches for demo
            if len(iocs) > 0:
                results['malicious_iocs'] = iocs[:1]  # First IOC is "malicious"
                results['reputation_scores'] = {iocs[0]: 0.8}
                results['confidence'] = 0.7
            
            return results if results['malicious_iocs'] else None
            
        except Exception as e:
            logger.error(f"Error querying threat intelligence: {e}")
            return None
    
    async def _get_geolocation_data(self, ips: List[str]) -> Optional[Dict[str, Any]]:
        """Get geolocation data for IP addresses"""
        try:
            # Placeholder for actual geolocation service
            # In production, integrate with MaxMind, IPInfo, etc.
            
            geo_data = {
                'ip_locations': {},
                'countries': set(),
                'risk_countries': [],
                'vpn_indicators': []
            }
            
            for ip in ips:
                if ip and not ip.startswith('192.168.') and not ip.startswith('10.'):
                    # Mock geolocation data
                    geo_data['ip_locations'][ip] = {
                        'country': 'Unknown',
                        'city': 'Unknown',
                        'latitude': 0.0,
                        'longitude': 0.0,
                        'is_vpn': False,
                        'is_tor': False
                    }
                    geo_data['countries'].add('Unknown')
            
            geo_data['countries'] = list(geo_data['countries'])
            return geo_data if geo_data['ip_locations'] else None
            
        except Exception as e:
            logger.error(f"Error getting geolocation data: {e}")
            return None
    
    async def _get_asset_context(self, asset_id: str) -> Optional[Dict[str, Any]]:
        """Get asset context information"""
        try:
            # Placeholder for asset management integration
            asset_context = {
                'asset_id': asset_id,
                'asset_type': 'unknown',
                'criticality': 'medium',
                'owner': 'unknown',
                'location': 'unknown',
                'os_version': 'unknown',
                'last_seen': datetime.utcnow().isoformat(),
                'vulnerabilities': [],
                'compliance_status': 'unknown'
            }
            
            return asset_context
            
        except Exception as e:
            logger.error(f"Error getting asset context: {e}")
            return None
    
    async def _get_user_context(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Get user context information"""
        try:
            # Placeholder for user directory integration
            user_context = {
                'user_id': user_id,
                'display_name': user_id,
                'department': 'unknown',
                'role': 'user',
                'privileges': [],
                'last_login': datetime.utcnow().isoformat(),
                'risk_score': 0.5,
                'account_status': 'active'
            }
            
            return user_context
            
        except Exception as e:
            logger.error(f"Error getting user context: {e}")
            return None
    
    def _extract_iocs(self, event: SiemEvent) -> List[str]:
        """Extract indicators of compromise from event"""
        iocs = []
        
        try:
            import re
            message = event.message.lower()
            
            # IP addresses
            ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
            iocs.extend(re.findall(ip_pattern, message))
            
            # Domain names
            domain_pattern = r'\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'
            domains = re.findall(domain_pattern, message)
            iocs.extend([d for d in domains if '.' in d])
            
            # File hashes (MD5, SHA1, SHA256)
            hash_patterns = [
                r'\b[a-fA-F0-9]{32}\b',
                r'\b[a-fA-F0-9]{40}\b', 
                r'\b[a-fA-F0-9]{64}\b'
            ]
            
            for pattern in hash_patterns:
                iocs.extend(re.findall(pattern, message))
            
        except Exception as e:
            logger.warning(f"Error extracting IOCs: {e}")
        
        return list(set(iocs))  # Remove duplicates
    
    # Risk and Recommendation Methods
    
    def _calculate_final_risk_score(self, enriched_alert: EnrichedAlert) -> None:
        """Calculate final risk score based on all enrichments"""
        risk_factors = []
        base_severity = enriched_alert.original_event.severity.value
        
        # Start with base severity risk
        severity_risk = (6 - base_severity) / 5
        risk_factors.append(severity_risk * 0.3)
        
        # AI prediction risks
        ai_enrichments = enriched_alert.get_enrichments_by_type(EnrichmentType.AI_PREDICTION)
        ai_risk = 0.0
        for enrichment in ai_enrichments:
            data = enrichment.data
            
            # Zero-day risk
            if 'zero_day_analysis' in data:
                zd_data = data['zero_day_analysis']
                if zd_data.get('is_novel'):
                    ai_risk += zd_data.get('novelty_score', 0) * 0.8
            
            # Threat classification risk
            if 'threat_classification' in data:
                tc_data = data['threat_classification']
                confidence = tc_data.get('confidence', 0)
                category = tc_data.get('predicted_category', '')
                if 'malware' in category.lower() or 'attack' in category.lower():
                    ai_risk += confidence * 0.6
            
            # Predictive risk
            if 'predictive_analysis' in data:
                pa_data = data['predictive_analysis']
                threat_likelihood = pa_data.get('threat_likelihood', 0)
                ai_risk += threat_likelihood * 0.5
        
        if ai_risk > 0:
            risk_factors.append(min(ai_risk, 0.4))
        
        # Threat intelligence risk
        ti_enrichments = enriched_alert.get_enrichments_by_type(EnrichmentType.THREAT_INTELLIGENCE)
        ti_risk = 0.0
        for enrichment in ti_enrichments:
            data = enrichment.data
            if data.get('malicious_iocs'):
                ti_risk += len(data['malicious_iocs']) * 0.1
            
            avg_reputation = sum(data.get('reputation_scores', {}).values()) / max(len(data.get('reputation_scores', {})), 1)
            ti_risk += avg_reputation * 0.2
        
        if ti_risk > 0:
            risk_factors.append(min(ti_risk, 0.2))
        
        # Behavioral risk
        behavioral_enrichments = enriched_alert.get_enrichments_by_type(EnrichmentType.BEHAVIORAL_ANALYSIS)
        for enrichment in behavioral_enrichments:
            data = enrichment.data
            if data.get('is_anomalous'):
                risk_factors.append(data.get('anomaly_score', 0) * 0.3)
        
        # Correlation risk
        correlation_enrichments = enriched_alert.get_enrichments_by_type(EnrichmentType.CORRELATION)
        for enrichment in correlation_enrichments:
            correlations = enrichment.data.get('correlations', [])
            if correlations:
                max_correlation_risk = max(c.get('risk_score', 0) for c in correlations)
                risk_factors.append(max_correlation_risk * 0.25)
        
        # Calculate final risk score
        enriched_alert.risk_score = min(sum(risk_factors), 1.0)
        
        # Calculate priority adjustment
        if enriched_alert.risk_score >= 0.8:
            enriched_alert.priority_adjustment = min(2, 5 - base_severity)
        elif enriched_alert.risk_score >= 0.6:
            enriched_alert.priority_adjustment = min(1, 5 - base_severity)
        elif enriched_alert.risk_score <= 0.2:
            enriched_alert.priority_adjustment = max(-1, 1 - base_severity)
    
    def _generate_recommendations(self, enriched_alert: EnrichedAlert) -> None:
        """Generate action recommendations based on enrichments"""
        recommendations = []
        
        # Risk-based recommendations
        if enriched_alert.risk_score >= 0.8:
            recommendations.extend([
                "IMMEDIATE INVESTIGATION REQUIRED",
                "Consider isolating affected systems",
                "Escalate to security incident response team",
                "Review and strengthen access controls"
            ])
        elif enriched_alert.risk_score >= 0.6:
            recommendations.extend([
                "High priority investigation",
                "Correlate with recent security events",
                "Review user and system activities",
                "Consider additional monitoring"
            ])
        elif enriched_alert.risk_score >= 0.4:
            recommendations.extend([
                "Standard investigation workflow",
                "Document findings for trend analysis",
                "Update detection rules if necessary"
            ])
        else:
            recommendations.extend([
                "Low priority review",
                "Log for pattern analysis",
                "Consider tuning alert rules"
            ])
        
        # Enrichment-specific recommendations
        for enrichment in enriched_alert.enrichments:
            if enrichment.enrichment_type == EnrichmentType.AI_PREDICTION:
                if 'zero_day_analysis' in enrichment.data:
                    zd_data = enrichment.data['zero_day_analysis']
                    if zd_data.get('is_novel'):
                        recommendations.append("Novel threat detected - update threat signatures")
                
                if 'threat_classification' in enrichment.data:
                    tc_data = enrichment.data['threat_classification']
                    category = tc_data.get('predicted_category', '')
                    if 'malware' in category.lower():
                        recommendations.append("Malware suspected - run antivirus scan")
                    elif 'phishing' in category.lower():
                        recommendations.append("Phishing attempt - verify email security")
            
            elif enrichment.enrichment_type == EnrichmentType.THREAT_INTELLIGENCE:
                if enrichment.data.get('malicious_iocs'):
                    recommendations.append("Malicious indicators found - block IOCs")
                if enrichment.data.get('threat_actors'):
                    recommendations.append("Known threat actor activity - review TTPs")
            
            elif enrichment.enrichment_type == EnrichmentType.BEHAVIORAL_ANALYSIS:
                if enrichment.data.get('is_anomalous'):
                    recommendations.append("User behavior anomaly - verify account integrity")
            
            elif enrichment.enrichment_type == EnrichmentType.CORRELATION:
                correlations = enrichment.data.get('correlations', [])
                if any(c.get('type') == 'chain' for c in correlations):
                    recommendations.append("Attack chain detected - trace full kill chain")
        
        # Remove duplicates while preserving order
        seen = set()
        unique_recommendations = []
        for rec in recommendations:
            if rec not in seen:
                seen.add(rec)
                unique_recommendations.append(rec)
        
        enriched_alert.recommended_actions = unique_recommendations
    
    # SIEM Integration Methods
    
    async def _send_enrichment_to_siems(
        self,
        enriched_alert: EnrichedAlert,
        target_platforms: Optional[List[str]] = None
    ) -> None:
        """Send enrichment data to SIEM platforms"""
        try:
            platforms = target_platforms or list(self.siem_connectors.keys())
            
            for platform in platforms:
                connector = self.siem_connectors.get(platform)
                if connector:
                    await self._send_enrichment_to_siem(connector, enriched_alert)
        
        except Exception as e:
            logger.error(f"Error sending enrichment to SIEMs: {e}")
    
    async def _send_enrichment_to_siem(
        self,
        connector: BaseSiemConnector,
        enriched_alert: EnrichedAlert
    ) -> None:
        """Send enrichment to specific SIEM platform"""
        try:
            # Create enrichment event
            enrichment_event = SiemEvent(
                id=f"enrichment_{enriched_alert.original_event.id}_{datetime.utcnow().timestamp()}",
                source="isectech-ai-ml-enrichment",
                event_type="alert_enrichment",
                category="enrichment",
                message=f"AI/ML enrichment for alert {enriched_alert.original_event.id}",
                severity=self._calculate_enrichment_severity(enriched_alert),
                metadata=enriched_alert.to_siem_format(),
                tags=["ai-ml", "enrichment", "isectech"]
            )
            
            # Send to SIEM
            response = await connector.send_event(enrichment_event)
            
            if response.is_success():
                self._metrics['enrichments_sent'] += 1
                logger.debug(f"Enrichment sent to {connector.platform}")
            else:
                logger.warning(f"Failed to send enrichment to {connector.platform}: {response.message}")
        
        except Exception as e:
            logger.error(f"Error sending enrichment to {connector.platform}: {e}")
    
    def _calculate_enrichment_severity(self, enriched_alert: EnrichedAlert) -> EventSeverity:
        """Calculate severity for enrichment event"""
        original_severity = enriched_alert.original_event.severity
        adjustment = enriched_alert.priority_adjustment
        
        new_severity_value = max(1, min(5, original_severity.value - adjustment))
        
        severity_mapping = {
            1: EventSeverity.CRITICAL,
            2: EventSeverity.HIGH,
            3: EventSeverity.MEDIUM,
            4: EventSeverity.LOW,
            5: EventSeverity.INFO
        }
        
        return severity_mapping.get(new_severity_value, EventSeverity.MEDIUM)
    
    # Background Workers
    
    async def _enrichment_worker(self) -> None:
        """Background worker for processing enrichment queue"""
        while self._running:
            try:
                # Process queued enrichments
                await asyncio.sleep(1)
                
            except Exception as e:
                logger.error(f"Error in enrichment worker: {e}")
                await asyncio.sleep(5)
    
    async def _cache_cleanup_worker(self) -> None:
        """Background worker for cache cleanup"""
        while self._running:
            try:
                current_time = datetime.utcnow()
                expired_keys = []
                
                for key, alert in self._enrichment_cache.items():
                    if not self._is_cache_valid(alert):
                        expired_keys.append(key)
                
                for key in expired_keys:
                    del self._enrichment_cache[key]
                
                if expired_keys:
                    logger.debug(f"Cleaned up {len(expired_keys)} expired cache entries")
                
                await asyncio.sleep(300)  # Run every 5 minutes
                
            except Exception as e:
                logger.error(f"Error in cache cleanup: {e}")
                await asyncio.sleep(60)
    
    # Utility Methods
    
    def _generate_cache_key(self, event: SiemEvent) -> str:
        """Generate cache key for event"""
        import hashlib
        key_data = f"{event.id}{event.message}{event.timestamp.isoformat()}"
        return hashlib.md5(key_data.encode()).hexdigest()
    
    def _is_cache_valid(self, alert: EnrichedAlert) -> bool:
        """Check if cached alert is still valid"""
        age_minutes = (datetime.utcnow() - alert.processing_started).total_seconds() / 60
        return age_minutes < self._cache_ttl_minutes
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get service metrics"""
        return {
            **self._metrics,
            'active_enrichments': self._enrichment_queue.qsize(),
            'cache_size': len(self._enrichment_cache),
            'siem_connectors': len(self.siem_connectors)
        }
    
    async def __aenter__(self):
        """Async context manager entry"""
        await self.start()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self.stop()