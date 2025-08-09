"""
SIEM Alert Manager

Production-grade alert management system that coordinates between 
AI/ML models, SIEM platforms, and response workflows.
"""

import asyncio
import logging
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
from uuid import uuid4

from .base_connector import SiemEvent, EventSeverity, BaseSiemConnector
from .correlation_engine import ThreatCorrelationEngine, CorrelationResult
from .enrichment_service import AlertEnrichmentService, EnrichedAlert

logger = logging.getLogger(__name__)

class AlertSeverity(Enum):
    """Alert severity levels"""
    CRITICAL = "critical"
    HIGH = "high" 
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class AlertStatus(str, Enum):
    """Alert status"""
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    CLOSED = "closed"
    FALSE_POSITIVE = "false_positive"

@dataclass
class AlertConfig:
    """Alert configuration"""
    auto_acknowledge_threshold: float = 0.9
    auto_escalate_threshold: float = 0.8
    auto_close_low_confidence: bool = True
    low_confidence_threshold: float = 0.3
    notification_channels: List[str] = field(default_factory=lambda: ["email", "slack"])
    escalation_delay_minutes: int = 30
    enable_correlation: bool = True
    enable_enrichment: bool = True
    max_alerts_per_hour: int = 1000

@dataclass
class Alert:
    """Alert data structure"""
    alert_id: str = field(default_factory=lambda: str(uuid4()))
    title: str = ""
    description: str = ""
    severity: AlertSeverity = AlertSeverity.MEDIUM
    status: AlertStatus = AlertStatus.NEW
    
    # Source information
    source_event: Optional[SiemEvent] = None
    correlation: Optional[CorrelationResult] = None
    enriched_data: Optional[EnrichedAlert] = None
    
    # Metadata
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    assigned_to: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    
    # AI/ML insights
    confidence_score: float = 0.0
    risk_score: float = 0.0
    ai_recommendations: List[str] = field(default_factory=list)
    
    # Workflow
    escalation_level: int = 0
    notifications_sent: List[str] = field(default_factory=list)
    actions_taken: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'alert_id': self.alert_id,
            'title': self.title,
            'description': self.description,
            'severity': self.severity.value,
            'status': self.status.value,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
            'assigned_to': self.assigned_to,
            'tags': self.tags,
            'confidence_score': self.confidence_score,
            'risk_score': self.risk_score,
            'ai_recommendations': self.ai_recommendations,
            'escalation_level': self.escalation_level,
            'notifications_sent': self.notifications_sent,
            'actions_taken': self.actions_taken,
            'source_event_id': self.source_event.id if self.source_event else None,
            'correlation_id': self.correlation.correlation_id if self.correlation else None
        }

class SiemAlertManager:
    """
    Production-grade SIEM alert manager
    
    Features:
    - Intelligent alert creation and prioritization
    - Automated correlation and enrichment
    - Configurable escalation workflows
    - Multi-channel notifications
    - Performance tracking and optimization
    - Integration with SOAR platforms
    """
    
    def __init__(
        self,
        config: AlertConfig,
        siem_connectors: List[BaseSiemConnector],
        correlation_engine: Optional[ThreatCorrelationEngine] = None,
        enrichment_service: Optional[AlertEnrichmentService] = None
    ):
        self.config = config
        self.siem_connectors = {conn.platform.value: conn for conn in siem_connectors}
        self.correlation_engine = correlation_engine
        self.enrichment_service = enrichment_service
        
        # Alert storage
        self._active_alerts: Dict[str, Alert] = {}
        self._alert_history: List[Alert] = []
        
        # Event handlers
        self._alert_handlers: List[Callable[[Alert], None]] = []
        self._escalation_handlers: List[Callable[[Alert], None]] = []
        
        # Rate limiting
        self._alert_count_by_hour: Dict[str, int] = {}
        
        # Background tasks
        self._escalation_task: Optional[asyncio.Task] = None
        self._cleanup_task: Optional[asyncio.Task] = None
        self._running = False
        
        # Metrics
        self._metrics = {
            'alerts_created': 0,
            'alerts_resolved': 0,
            'alerts_escalated': 0,
            'false_positives': 0,
            'average_resolution_time_minutes': 0.0,
            'notifications_sent': 0,
            'auto_actions_taken': 0
        }
        
        logger.info("SIEM Alert Manager initialized")
    
    async def start(self) -> None:
        """Start the alert manager"""
        if self._running:
            return
        
        self._running = True
        
        # Start background tasks
        self._escalation_task = asyncio.create_task(self._escalation_worker())
        self._cleanup_task = asyncio.create_task(self._cleanup_worker())
        
        logger.info("SIEM Alert Manager started")
    
    async def stop(self) -> None:
        """Stop the alert manager"""
        self._running = False
        
        # Cancel background tasks
        if self._escalation_task:
            self._escalation_task.cancel()
        if self._cleanup_task:
            self._cleanup_task.cancel()
        
        # Wait for tasks to complete
        tasks = [self._escalation_task, self._cleanup_task]
        await asyncio.gather(*[t for t in tasks if t], return_exceptions=True)
        
        logger.info("SIEM Alert Manager stopped")
    
    async def create_alert_from_event(self, event: SiemEvent) -> Optional[Alert]:
        """Create alert from SIEM event"""
        try:
            # Check rate limits
            if not self._check_rate_limit():
                logger.warning("Alert creation rate limit exceeded")
                return None
            
            # Create base alert
            alert = Alert(
                title=f"Security Event: {event.event_type}",
                description=event.message,
                severity=self._map_event_severity(event.severity),
                source_event=event,
                tags=[event.category, event.event_type, event.source]
            )
            
            # Enhance with correlation
            if self.config.enable_correlation and self.correlation_engine:
                correlations = await self.correlation_engine.process_event(event)
                if correlations:
                    # Use the highest confidence correlation
                    best_correlation = max(correlations, key=lambda c: c.confidence_score)
                    alert.correlation = best_correlation
                    alert.confidence_score = best_correlation.confidence_score
                    alert.risk_score = best_correlation.risk_score
                    alert.ai_recommendations.extend(best_correlation.recommended_actions)
                    
                    # Update severity based on correlation
                    if best_correlation.priority_level == EventSeverity.CRITICAL:
                        alert.severity = AlertSeverity.CRITICAL
                    elif best_correlation.priority_level == EventSeverity.HIGH:
                        alert.severity = AlertSeverity.HIGH
            
            # Enhance with enrichment
            if self.config.enable_enrichment and self.enrichment_service:
                try:
                    enriched_alert = await self.enrichment_service.enrich_alert(event)
                    alert.enriched_data = enriched_alert
                    
                    if enriched_alert.total_confidence > alert.confidence_score:
                        alert.confidence_score = enriched_alert.total_confidence
                    
                    if enriched_alert.risk_score > alert.risk_score:
                        alert.risk_score = enriched_alert.risk_score
                    
                    alert.ai_recommendations.extend(enriched_alert.recommended_actions)
                    
                except Exception as e:
                    logger.warning(f"Enrichment failed for event {event.id}: {e}")
            
            # Apply automated decisions
            await self._apply_automated_decisions(alert)
            
            # Store alert
            self._active_alerts[alert.alert_id] = alert
            self._metrics['alerts_created'] += 1
            
            # Send notifications
            await self._send_alert_notifications(alert)
            
            # Notify handlers
            await self._notify_alert_handlers(alert)
            
            # Send to SIEM platforms
            await self._send_alert_to_siems(alert)
            
            logger.info(f"Created alert {alert.alert_id} from event {event.id}")
            return alert
            
        except Exception as e:
            logger.error(f"Error creating alert from event {event.id}: {e}")
            return None
    
    async def create_alert_from_correlation(self, correlation: CorrelationResult) -> Optional[Alert]:
        """Create alert from threat correlation"""
        try:
            # Check rate limits
            if not self._check_rate_limit():
                logger.warning("Alert creation rate limit exceeded")
                return None
            
            # Create alert from correlation
            alert = Alert(
                title=f"Threat Correlation: {correlation.correlation_type.value}",
                description=f"Correlated {len(correlation.events)} events indicating potential {correlation.correlation_type.value} threat",
                severity=self._map_correlation_severity(correlation),
                correlation=correlation,
                confidence_score=correlation.confidence_score,
                risk_score=correlation.risk_score,
                ai_recommendations=correlation.recommended_actions.copy(),
                tags=[correlation.correlation_type.value, "correlation", "ai-generated"]
            )
            
            # Store alert
            self._active_alerts[alert.alert_id] = alert
            self._metrics['alerts_created'] += 1
            
            # Apply automated decisions
            await self._apply_automated_decisions(alert)
            
            # Send notifications
            await self._send_alert_notifications(alert)
            
            # Notify handlers
            await self._notify_alert_handlers(alert)
            
            # Send to SIEM platforms
            await self._send_alert_to_siems(alert)
            
            logger.info(f"Created alert {alert.alert_id} from correlation {correlation.correlation_id}")
            return alert
            
        except Exception as e:
            logger.error(f"Error creating alert from correlation {correlation.correlation_id}: {e}")
            return None
    
    async def update_alert_status(self, alert_id: str, status: AlertStatus, assigned_to: Optional[str] = None) -> bool:
        """Update alert status"""
        try:
            if alert_id not in self._active_alerts:
                logger.warning(f"Alert {alert_id} not found")
                return False
            
            alert = self._active_alerts[alert_id]
            old_status = alert.status
            
            alert.status = status
            alert.updated_at = datetime.utcnow()
            
            if assigned_to:
                alert.assigned_to = assigned_to
            
            # Track metrics
            if status in [AlertStatus.RESOLVED, AlertStatus.CLOSED]:
                self._metrics['alerts_resolved'] += 1
                
                # Calculate resolution time
                resolution_time = (alert.updated_at - alert.created_at).total_seconds() / 60
                self._metrics['average_resolution_time_minutes'] = (
                    (self._metrics['average_resolution_time_minutes'] * (self._metrics['alerts_resolved'] - 1) + resolution_time) /
                    self._metrics['alerts_resolved']
                )
                
                # Move to history
                self._alert_history.append(alert)
                del self._active_alerts[alert_id]
            
            elif status == AlertStatus.FALSE_POSITIVE:
                self._metrics['false_positives'] += 1
                self._alert_history.append(alert)
                del self._active_alerts[alert_id]
            
            # Add action to history
            alert.actions_taken.append(f"Status changed from {old_status.value} to {status.value} at {alert.updated_at.isoformat()}")
            
            # Send status update to SIEM platforms
            await self._send_status_update_to_siems(alert)
            
            logger.info(f"Updated alert {alert_id} status to {status.value}")
            return True
            
        except Exception as e:
            logger.error(f"Error updating alert status: {e}")
            return False
    
    async def _apply_automated_decisions(self, alert: Alert) -> None:
        """Apply automated decisions based on configuration and AI insights"""
        try:
            # Auto-acknowledge high confidence alerts
            if (alert.confidence_score >= self.config.auto_acknowledge_threshold and 
                alert.status == AlertStatus.NEW):
                alert.status = AlertStatus.ACKNOWLEDGED
                alert.actions_taken.append(f"Auto-acknowledged due to high confidence ({alert.confidence_score:.2f})")
                self._metrics['auto_actions_taken'] += 1
            
            # Auto-close low confidence alerts
            if (self.config.auto_close_low_confidence and 
                alert.confidence_score <= self.config.low_confidence_threshold and
                alert.severity in [AlertSeverity.LOW, AlertSeverity.INFO]):
                alert.status = AlertStatus.CLOSED
                alert.actions_taken.append(f"Auto-closed due to low confidence ({alert.confidence_score:.2f})")
                self._metrics['auto_actions_taken'] += 1
            
            # Auto-escalate high-risk alerts
            if (alert.risk_score >= self.config.auto_escalate_threshold and
                alert.severity in [AlertSeverity.CRITICAL, AlertSeverity.HIGH]):
                alert.escalation_level = 1
                alert.actions_taken.append(f"Auto-escalated due to high risk score ({alert.risk_score:.2f})")
                self._metrics['auto_actions_taken'] += 1
                await self._notify_escalation_handlers(alert)
            
        except Exception as e:
            logger.error(f"Error applying automated decisions: {e}")
    
    async def _send_alert_notifications(self, alert: Alert) -> None:
        """Send alert notifications through configured channels"""
        try:
            for channel in self.config.notification_channels:
                if channel == "email":
                    await self._send_email_notification(alert)
                elif channel == "slack":
                    await self._send_slack_notification(alert)
                elif channel == "webhook":
                    await self._send_webhook_notification(alert)
                
                alert.notifications_sent.append(f"{channel}:{datetime.utcnow().isoformat()}")
                self._metrics['notifications_sent'] += 1
            
        except Exception as e:
            logger.error(f"Error sending alert notifications: {e}")
    
    async def _send_email_notification(self, alert: Alert) -> None:
        """Send email notification (placeholder)"""
        # In production, integrate with email service
        logger.info(f"Email notification sent for alert {alert.alert_id}")
    
    async def _send_slack_notification(self, alert: Alert) -> None:
        """Send Slack notification (placeholder)"""
        # In production, integrate with Slack API
        logger.info(f"Slack notification sent for alert {alert.alert_id}")
    
    async def _send_webhook_notification(self, alert: Alert) -> None:
        """Send webhook notification (placeholder)"""
        # In production, send HTTP POST to webhook URL
        logger.info(f"Webhook notification sent for alert {alert.alert_id}")
    
    async def _send_alert_to_siems(self, alert: Alert) -> None:
        """Send alert to SIEM platforms"""
        try:
            for platform, connector in self.siem_connectors.items():
                try:
                    # Create SIEM alert
                    response = await connector.create_alert(
                        title=alert.title,
                        description=self._generate_alert_description(alert),
                        severity=self._map_alert_severity_to_siem(alert.severity),
                        metadata=alert.to_dict()
                    )
                    
                    if response.is_success():
                        logger.debug(f"Alert sent to {platform}")
                        alert.actions_taken.append(f"Sent to {platform} at {datetime.utcnow().isoformat()}")
                    else:
                        logger.warning(f"Failed to send alert to {platform}: {response.message}")
                
                except Exception as e:
                    logger.error(f"Error sending alert to {platform}: {e}")
            
        except Exception as e:
            logger.error(f"Error sending alert to SIEMs: {e}")
    
    async def _send_status_update_to_siems(self, alert: Alert) -> None:
        """Send alert status update to SIEM platforms"""
        try:
            # Create status update event
            status_event = SiemEvent(
                id=f"alert_status_{alert.alert_id}_{datetime.utcnow().timestamp()}",
                source="isectech-alert-manager",
                event_type="alert_status_update",
                category="alert_management",
                message=f"Alert {alert.alert_id} status updated to {alert.status.value}",
                severity=EventSeverity.INFO,
                metadata={
                    'alert_id': alert.alert_id,
                    'old_status': alert.status.value,
                    'new_status': alert.status.value,
                    'assigned_to': alert.assigned_to
                }
            )
            
            # Send to all SIEM connectors
            for platform, connector in self.siem_connectors.items():
                try:
                    await connector.send_event(status_event)
                except Exception as e:
                    logger.warning(f"Failed to send status update to {platform}: {e}")
            
        except Exception as e:
            logger.error(f"Error sending status update to SIEMs: {e}")
    
    def _generate_alert_description(self, alert: Alert) -> str:
        """Generate detailed alert description for SIEM"""
        description = f"Alert ID: {alert.alert_id}\n"
        description += f"Created: {alert.created_at.isoformat()}\n"
        description += f"Severity: {alert.severity.value}\n"
        description += f"Confidence: {alert.confidence_score:.2f}\n"
        description += f"Risk Score: {alert.risk_score:.2f}\n"
        description += f"\nDescription:\n{alert.description}\n"
        
        if alert.ai_recommendations:
            description += f"\nAI Recommendations:\n"
            for rec in alert.ai_recommendations:
                description += f"- {rec}\n"
        
        if alert.source_event:
            description += f"\nSource Event: {alert.source_event.id}\n"
        
        if alert.correlation:
            description += f"\nCorrelation: {alert.correlation.correlation_id} ({alert.correlation.correlation_type.value})\n"
        
        return description
    
    def _check_rate_limit(self) -> bool:
        """Check if alert creation is within rate limits"""
        current_hour = datetime.utcnow().strftime("%Y-%m-%d-%H")
        
        if current_hour not in self._alert_count_by_hour:
            self._alert_count_by_hour[current_hour] = 0
        
        if self._alert_count_by_hour[current_hour] >= self.config.max_alerts_per_hour:
            return False
        
        self._alert_count_by_hour[current_hour] += 1
        return True
    
    def _map_event_severity(self, event_severity: EventSeverity) -> AlertSeverity:
        """Map event severity to alert severity"""
        mapping = {
            EventSeverity.CRITICAL: AlertSeverity.CRITICAL,
            EventSeverity.HIGH: AlertSeverity.HIGH,
            EventSeverity.MEDIUM: AlertSeverity.MEDIUM,
            EventSeverity.LOW: AlertSeverity.LOW,
            EventSeverity.INFO: AlertSeverity.INFO
        }
        return mapping.get(event_severity, AlertSeverity.MEDIUM)
    
    def _map_correlation_severity(self, correlation: CorrelationResult) -> AlertSeverity:
        """Map correlation to alert severity"""
        if correlation.risk_score >= 0.8:
            return AlertSeverity.CRITICAL
        elif correlation.risk_score >= 0.6:
            return AlertSeverity.HIGH
        elif correlation.risk_score >= 0.4:
            return AlertSeverity.MEDIUM
        elif correlation.risk_score >= 0.2:
            return AlertSeverity.LOW
        else:
            return AlertSeverity.INFO
    
    def _map_alert_severity_to_siem(self, alert_severity: AlertSeverity) -> EventSeverity:
        """Map alert severity back to SIEM event severity"""
        mapping = {
            AlertSeverity.CRITICAL: EventSeverity.CRITICAL,
            AlertSeverity.HIGH: EventSeverity.HIGH,
            AlertSeverity.MEDIUM: EventSeverity.MEDIUM,
            AlertSeverity.LOW: EventSeverity.LOW,
            AlertSeverity.INFO: EventSeverity.INFO
        }
        return mapping.get(alert_severity, EventSeverity.MEDIUM)
    
    async def _escalation_worker(self) -> None:
        """Background worker for alert escalation"""
        while self._running:
            try:
                current_time = datetime.utcnow()
                
                for alert in list(self._active_alerts.values()):
                    # Check if alert needs escalation
                    time_since_created = (current_time - alert.created_at).total_seconds() / 60
                    
                    if (alert.status in [AlertStatus.NEW, AlertStatus.ACKNOWLEDGED] and
                        alert.severity in [AlertSeverity.CRITICAL, AlertSeverity.HIGH] and
                        time_since_created >= self.config.escalation_delay_minutes and
                        alert.escalation_level == 0):
                        
                        alert.escalation_level = 1
                        alert.updated_at = current_time
                        alert.actions_taken.append(f"Auto-escalated after {self.config.escalation_delay_minutes} minutes")
                        
                        await self._notify_escalation_handlers(alert)
                        self._metrics['alerts_escalated'] += 1
                        
                        logger.info(f"Escalated alert {alert.alert_id}")
                
                await asyncio.sleep(60)  # Check every minute
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in escalation worker: {e}")
                await asyncio.sleep(10)
    
    async def _cleanup_worker(self) -> None:
        """Background worker for cleanup tasks"""
        while self._running:
            try:
                # Clean up old rate limit data
                current_time = datetime.utcnow()
                old_hours = []
                
                for hour_key in self._alert_count_by_hour:
                    hour_time = datetime.strptime(hour_key, "%Y-%m-%d-%H")
                    if (current_time - hour_time).total_seconds() > 86400:  # Older than 24 hours
                        old_hours.append(hour_key)
                
                for hour_key in old_hours:
                    del self._alert_count_by_hour[hour_key]
                
                # Clean up old alert history
                cutoff_time = current_time - timedelta(days=30)
                self._alert_history = [
                    alert for alert in self._alert_history
                    if alert.updated_at > cutoff_time
                ]
                
                await asyncio.sleep(3600)  # Run every hour
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in cleanup worker: {e}")
                await asyncio.sleep(300)
    
    async def _notify_alert_handlers(self, alert: Alert) -> None:
        """Notify alert event handlers"""
        for handler in self._alert_handlers:
            try:
                if asyncio.iscoroutinefunction(handler):
                    await handler(alert)
                else:
                    handler(alert)
            except Exception as e:
                logger.warning(f"Error in alert handler: {e}")
    
    async def _notify_escalation_handlers(self, alert: Alert) -> None:
        """Notify escalation handlers"""
        for handler in self._escalation_handlers:
            try:
                if asyncio.iscoroutinefunction(handler):
                    await handler(alert)
                else:
                    handler(alert)
            except Exception as e:
                logger.warning(f"Error in escalation handler: {e}")
    
    # Public API methods
    
    def add_alert_handler(self, handler: Callable[[Alert], None]) -> None:
        """Add alert event handler"""
        self._alert_handlers.append(handler)
    
    def add_escalation_handler(self, handler: Callable[[Alert], None]) -> None:
        """Add escalation handler"""
        self._escalation_handlers.append(handler)
    
    def remove_alert_handler(self, handler: Callable[[Alert], None]) -> None:
        """Remove alert handler"""
        if handler in self._alert_handlers:
            self._alert_handlers.remove(handler)
    
    def remove_escalation_handler(self, handler: Callable[[Alert], None]) -> None:
        """Remove escalation handler"""
        if handler in self._escalation_handlers:
            self._escalation_handlers.remove(handler)
    
    def get_active_alerts(self) -> List[Alert]:
        """Get all active alerts"""
        return list(self._active_alerts.values())
    
    def get_alert(self, alert_id: str) -> Optional[Alert]:
        """Get specific alert"""
        return self._active_alerts.get(alert_id)
    
    def get_alerts_by_status(self, status: AlertStatus) -> List[Alert]:
        """Get alerts by status"""
        return [alert for alert in self._active_alerts.values() if alert.status == status]
    
    def get_alerts_by_severity(self, severity: AlertSeverity) -> List[Alert]:
        """Get alerts by severity"""
        return [alert for alert in self._active_alerts.values() if alert.severity == severity]
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get alert manager metrics"""
        return {
            **self._metrics,
            'active_alerts': len(self._active_alerts),
            'alert_history_size': len(self._alert_history),
            'current_hour_alerts': self._alert_count_by_hour.get(datetime.utcnow().strftime("%Y-%m-%d-%H"), 0)
        }
    
    async def __aenter__(self):
        """Async context manager entry"""
        await self.start()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self.stop()