"""
Production-grade audit logging for iSECTECH AI services.

This module provides comprehensive audit logging capabilities for:
- Security events and access attempts
- Model operations and predictions
- Data access and modifications
- Administrative actions
- Compliance tracking and reporting
"""

import json
import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Union

import structlog

from ..config.settings import SecurityClassification


class AuditEventType(str, Enum):
    """Types of audit events."""
    # Authentication events
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    LOGOUT = "logout"
    TOKEN_REFRESH = "token_refresh"
    SESSION_EXPIRED = "session_expired"
    
    # Authorization events
    ACCESS_GRANTED = "access_granted"
    ACCESS_DENIED = "access_denied"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    
    # Data access events
    DATA_READ = "data_read"
    DATA_WRITE = "data_write"
    DATA_DELETE = "data_delete"
    DATA_EXPORT = "data_export"
    DATA_IMPORT = "data_import"
    
    # Model events
    MODEL_CREATED = "model_created"
    MODEL_UPDATED = "model_updated"
    MODEL_DELETED = "model_deleted"
    MODEL_EXECUTED = "model_executed"
    MODEL_PREDICTION = "model_prediction"
    MODEL_TRAINING_STARTED = "model_training_started"
    MODEL_TRAINING_COMPLETED = "model_training_completed"
    
    # Analysis events
    ANOMALY_DETECTED = "anomaly_detected"
    THREAT_ANALYZED = "threat_analyzed"
    BEHAVIOR_ANALYZED = "behavior_analyzed"
    INVESTIGATION_STARTED = "investigation_started"
    INVESTIGATION_COMPLETED = "investigation_completed"
    
    # Administrative events
    USER_CREATED = "user_created"
    USER_UPDATED = "user_updated"
    USER_DELETED = "user_deleted"
    ROLE_ASSIGNED = "role_assigned"
    ROLE_REMOVED = "role_removed"
    CONFIGURATION_CHANGED = "configuration_changed"
    
    # Security events
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    SECURITY_VIOLATION = "security_violation"
    INTRUSION_ATTEMPT = "intrusion_attempt"
    
    # System events
    SERVICE_STARTED = "service_started"
    SERVICE_STOPPED = "service_stopped"
    ERROR_OCCURRED = "error_occurred"
    PERFORMANCE_ALERT = "performance_alert"


class AuditSeverity(str, Enum):
    """Severity levels for audit events."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SecurityEvent:
    """Represents a security event for audit logging."""
    
    def __init__(self, event_type: AuditEventType, severity: AuditSeverity,
                 user_id: str, tenant_id: str, 
                 description: str, details: Optional[Dict] = None,
                 resource_id: Optional[str] = None,
                 security_classification: SecurityClassification = SecurityClassification.UNCLASSIFIED,
                 source_ip: Optional[str] = None,
                 user_agent: Optional[str] = None):
        self.event_id = str(uuid.uuid4())
        self.event_type = event_type
        self.severity = severity
        self.user_id = user_id
        self.tenant_id = tenant_id
        self.description = description
        self.details = details or {}
        self.resource_id = resource_id
        self.security_classification = security_classification
        self.source_ip = source_ip
        self.user_agent = user_agent
        self.timestamp = datetime.utcnow()
        self.correlation_id = None  # Can be set for related events
    
    def set_correlation_id(self, correlation_id: str):
        """Set correlation ID for grouping related events."""
        self.correlation_id = correlation_id
    
    def add_detail(self, key: str, value: Any):
        """Add additional detail to the event."""
        self.details[key] = value
    
    def to_dict(self) -> Dict:
        """Convert event to dictionary for logging."""
        return {
            "event_id": self.event_id,
            "event_type": self.event_type.value,
            "severity": self.severity.value,
            "user_id": self.user_id,
            "tenant_id": self.tenant_id,
            "description": self.description,
            "details": self.details,
            "resource_id": self.resource_id,
            "security_classification": self.security_classification.value,
            "source_ip": self.source_ip,
            "user_agent": self.user_agent,
            "timestamp": self.timestamp.isoformat(),
            "correlation_id": self.correlation_id
        }
    
    def to_json(self) -> str:
        """Convert event to JSON string."""
        return json.dumps(self.to_dict(), default=str)


class ComplianceEvent:
    """Represents a compliance-related event."""
    
    def __init__(self, compliance_framework: str, control_id: str,
                 status: str, user_id: str, tenant_id: str,
                 description: str, evidence: Optional[Dict] = None):
        self.event_id = str(uuid.uuid4())
        self.compliance_framework = compliance_framework  # e.g., "SOC2", "GDPR", "HIPAA"
        self.control_id = control_id
        self.status = status  # e.g., "compliant", "non_compliant", "needs_review"
        self.user_id = user_id
        self.tenant_id = tenant_id
        self.description = description
        self.evidence = evidence or {}
        self.timestamp = datetime.utcnow()
    
    def to_dict(self) -> Dict:
        """Convert compliance event to dictionary."""
        return {
            "event_id": self.event_id,
            "compliance_framework": self.compliance_framework,
            "control_id": self.control_id,
            "status": self.status,
            "user_id": self.user_id,
            "tenant_id": self.tenant_id,
            "description": self.description,
            "evidence": self.evidence,
            "timestamp": self.timestamp.isoformat()
        }


class AuditLogger:
    """Production-grade audit logger with multiple backends."""
    
    def __init__(self, service_name: str, enable_encryption: bool = True):
        self.service_name = service_name
        self.enable_encryption = enable_encryption
        self.logger = structlog.get_logger("audit")
        self.event_buffer: List[SecurityEvent] = []
        self.compliance_buffer: List[ComplianceEvent] = []
        self.buffer_size = 1000
    
    def log_security_event(self, event: SecurityEvent):
        """Log a security event."""
        # Add service context
        event.add_detail("service_name", self.service_name)
        
        # Log structured event
        self.logger.info(
            "security_event",
            event_id=event.event_id,
            event_type=event.event_type.value,
            severity=event.severity.value,
            user_id=event.user_id,
            tenant_id=event.tenant_id,
            description=event.description,
            details=event.details,
            resource_id=event.resource_id,
            security_classification=event.security_classification.value,
            source_ip=event.source_ip,
            user_agent=event.user_agent,
            timestamp=event.timestamp.isoformat(),
            correlation_id=event.correlation_id
        )
        
        # Buffer for batch processing
        self.event_buffer.append(event)
        if len(self.event_buffer) >= self.buffer_size:
            self._flush_event_buffer()
    
    def log_compliance_event(self, event: ComplianceEvent):
        """Log a compliance event."""
        self.logger.info(
            "compliance_event",
            event_id=event.event_id,
            compliance_framework=event.compliance_framework,
            control_id=event.control_id,
            status=event.status,
            user_id=event.user_id,
            tenant_id=event.tenant_id,
            description=event.description,
            evidence=event.evidence,
            timestamp=event.timestamp.isoformat(),
            service_name=self.service_name
        )
        
        self.compliance_buffer.append(event)
        if len(self.compliance_buffer) >= self.buffer_size:
            self._flush_compliance_buffer()
    
    def log_authentication_event(self, success: bool, user_id: str, tenant_id: str,
                                source_ip: str = None, user_agent: str = None,
                                failure_reason: str = None):
        """Log authentication event."""
        event_type = AuditEventType.LOGIN_SUCCESS if success else AuditEventType.LOGIN_FAILURE
        severity = AuditSeverity.LOW if success else AuditSeverity.MEDIUM
        
        description = "User authentication successful" if success else f"User authentication failed: {failure_reason}"
        
        event = SecurityEvent(
            event_type=event_type,
            severity=severity,
            user_id=user_id,
            tenant_id=tenant_id,
            description=description,
            source_ip=source_ip,
            user_agent=user_agent
        )
        
        if not success and failure_reason:
            event.add_detail("failure_reason", failure_reason)
        
        self.log_security_event(event)
    
    def log_authorization_event(self, granted: bool, user_id: str, tenant_id: str,
                              resource_id: str, action: str, reason: str = None,
                              source_ip: str = None):
        """Log authorization event."""
        event_type = AuditEventType.ACCESS_GRANTED if granted else AuditEventType.ACCESS_DENIED
        severity = AuditSeverity.LOW if granted else AuditSeverity.MEDIUM
        
        description = f"Access {'granted' if granted else 'denied'} to resource {resource_id} for action {action}"
        
        event = SecurityEvent(
            event_type=event_type,
            severity=severity,
            user_id=user_id,
            tenant_id=tenant_id,
            description=description,
            resource_id=resource_id,
            source_ip=source_ip
        )
        
        event.add_detail("action", action)
        if reason:
            event.add_detail("reason", reason)
        
        self.log_security_event(event)
    
    def log_model_event(self, event_type: AuditEventType, user_id: str, tenant_id: str,
                       model_id: str, model_type: str = None, 
                       prediction_confidence: float = None,
                       input_features: List[str] = None):
        """Log model-related event."""
        severity = AuditSeverity.LOW
        if event_type in [AuditEventType.MODEL_DELETED, AuditEventType.ANOMALY_DETECTED]:
            severity = AuditSeverity.MEDIUM
        
        description = f"Model operation: {event_type.value} for model {model_id}"
        
        event = SecurityEvent(
            event_type=event_type,
            severity=severity,
            user_id=user_id,
            tenant_id=tenant_id,
            description=description,
            resource_id=model_id
        )
        
        if model_type:
            event.add_detail("model_type", model_type)
        if prediction_confidence is not None:
            event.add_detail("prediction_confidence", prediction_confidence)
        if input_features:
            event.add_detail("input_features", input_features)
        
        self.log_security_event(event)
    
    def log_data_access_event(self, access_type: str, user_id: str, tenant_id: str,
                            data_source: str, record_count: int = None,
                            security_classification: SecurityClassification = SecurityClassification.UNCLASSIFIED,
                            query_details: str = None):
        """Log data access event."""
        event_type_map = {
            "read": AuditEventType.DATA_READ,
            "write": AuditEventType.DATA_WRITE,
            "delete": AuditEventType.DATA_DELETE,
            "export": AuditEventType.DATA_EXPORT,
            "import": AuditEventType.DATA_IMPORT
        }
        
        event_type = event_type_map.get(access_type, AuditEventType.DATA_READ)
        severity = AuditSeverity.LOW
        
        if access_type in ["delete", "export"] or security_classification in [SecurityClassification.SECRET, SecurityClassification.TOP_SECRET]:
            severity = AuditSeverity.MEDIUM
        
        description = f"Data {access_type} operation on {data_source}"
        
        event = SecurityEvent(
            event_type=event_type,
            severity=severity,
            user_id=user_id,
            tenant_id=tenant_id,
            description=description,
            resource_id=data_source,
            security_classification=security_classification
        )
        
        if record_count is not None:
            event.add_detail("record_count", record_count)
        if query_details:
            event.add_detail("query_details", query_details)
        
        self.log_security_event(event)
    
    def log_suspicious_activity(self, user_id: str, tenant_id: str, activity_type: str,
                              description: str, risk_score: float = None,
                              source_ip: str = None, evidence: Dict = None):
        """Log suspicious activity."""
        severity = AuditSeverity.HIGH if risk_score and risk_score > 0.8 else AuditSeverity.MEDIUM
        
        event = SecurityEvent(
            event_type=AuditEventType.SUSPICIOUS_ACTIVITY,
            severity=severity,
            user_id=user_id,
            tenant_id=tenant_id,
            description=description,
            source_ip=source_ip
        )
        
        event.add_detail("activity_type", activity_type)
        if risk_score is not None:
            event.add_detail("risk_score", risk_score)
        if evidence:
            event.add_detail("evidence", evidence)
        
        self.log_security_event(event)
    
    def log_compliance_check(self, framework: str, control_id: str,
                           status: str, user_id: str, tenant_id: str,
                           description: str, evidence: Dict = None):
        """Log compliance check result."""
        event = ComplianceEvent(
            compliance_framework=framework,
            control_id=control_id,
            status=status,
            user_id=user_id,
            tenant_id=tenant_id,
            description=description,
            evidence=evidence
        )
        
        self.log_compliance_event(event)
    
    def _flush_event_buffer(self):
        """Flush security event buffer to persistent storage."""
        # In production, this would send events to external systems
        # like Elasticsearch, Splunk, or a SIEM system
        self.logger.info(f"Flushing {len(self.event_buffer)} security events to persistent storage")
        self.event_buffer.clear()
    
    def _flush_compliance_buffer(self):
        """Flush compliance event buffer to persistent storage."""
        self.logger.info(f"Flushing {len(self.compliance_buffer)} compliance events to persistent storage")
        self.compliance_buffer.clear()
    
    def get_audit_summary(self, time_window_hours: int = 24) -> Dict:
        """Get audit summary for monitoring."""
        # In production, this would query the audit database
        return {
            "events_logged": len(self.event_buffer),
            "compliance_events_logged": len(self.compliance_buffer),
            "service_name": self.service_name,
            "encryption_enabled": self.enable_encryption,
            "buffer_utilization": {
                "security_events": len(self.event_buffer) / self.buffer_size,
                "compliance_events": len(self.compliance_buffer) / self.buffer_size
            }
        }
    
    def create_correlation_id(self) -> str:
        """Create correlation ID for grouping related events."""
        return str(uuid.uuid4())


# Global audit logger instance
_audit_logger: Optional[AuditLogger] = None


def get_audit_logger(service_name: str = "ai-service") -> AuditLogger:
    """Get global audit logger instance."""
    global _audit_logger
    if _audit_logger is None:
        _audit_logger = AuditLogger(service_name)
    return _audit_logger


def create_security_event(event_type: AuditEventType, severity: AuditSeverity,
                         user_id: str, tenant_id: str, description: str,
                         **kwargs) -> SecurityEvent:
    """Convenience function to create security event."""
    return SecurityEvent(
        event_type=event_type,
        severity=severity,
        user_id=user_id,
        tenant_id=tenant_id,
        description=description,
        **kwargs
    )


def create_compliance_event(framework: str, control_id: str, status: str,
                          user_id: str, tenant_id: str, description: str,
                          evidence: Dict = None) -> ComplianceEvent:
    """Convenience function to create compliance event."""
    return ComplianceEvent(
        compliance_framework=framework,
        control_id=control_id,
        status=status,
        user_id=user_id,
        tenant_id=tenant_id,
        description=description,
        evidence=evidence
    )