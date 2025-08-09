"""
Comprehensive Audit Trail Generation System
Production-grade audit logging and compliance reporting for AI/ML systems
"""

import logging
import json
import asyncio
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
import uuid
import aioredis
from sqlalchemy import create_engine, Column, String, DateTime, Text, Boolean, JSON, Integer, Float
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import base64

logger = logging.getLogger(__name__)

class AuditEventType(Enum):
    """Types of auditable events"""
    USER_AUTHENTICATION = "user_authentication"
    DATA_ACCESS = "data_access"
    MODEL_TRAINING = "model_training"
    MODEL_INFERENCE = "model_inference"
    DATA_MODIFICATION = "data_modification"
    CONFIGURATION_CHANGE = "configuration_change"
    SECURITY_EVENT = "security_event"
    COMPLIANCE_EVENT = "compliance_event"
    SYSTEM_EVENT = "system_event"
    API_REQUEST = "api_request"

class AuditSeverity(Enum):
    """Audit event severity levels"""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"

class AuditStatus(Enum):
    """Audit record status"""
    ACTIVE = "active"
    ARCHIVED = "archived"
    DELETED = "deleted"

@dataclass
class AuditEvent:
    """Comprehensive audit event record"""
    event_id: str
    timestamp: datetime
    event_type: AuditEventType
    severity: AuditSeverity
    user_id: Optional[str]
    session_id: Optional[str]
    source_ip: Optional[str]
    user_agent: Optional[str]
    action: str
    resource: str
    resource_type: str
    outcome: str  # "success", "failure", "partial"
    details: Dict[str, Any]
    sensitive_data_accessed: bool
    data_classification: Optional[str]
    compliance_frameworks: List[str]
    retention_period: int  # days
    digital_signature: Optional[str]
    
    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data['timestamp'] = self.timestamp.isoformat()
        data['event_type'] = self.event_type.value
        data['severity'] = self.severity.value
        return data

@dataclass 
class AuditQuery:
    """Audit trail query parameters"""
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    user_id: Optional[str] = None
    event_types: Optional[List[AuditEventType]] = None
    severities: Optional[List[AuditSeverity]] = None
    resource: Optional[str] = None
    outcome: Optional[str] = None
    sensitive_data_only: bool = False
    limit: int = 1000
    offset: int = 0

@dataclass
class AuditIntegrityCheck:
    """Audit trail integrity verification result"""
    check_id: str
    timestamp: datetime
    total_records_checked: int
    integrity_violations: int
    tampered_records: List[str]
    missing_records: List[str]
    signature_failures: List[str]
    overall_integrity: bool
    confidence_score: float

class AuditTrailDB:
    """Database models for audit trail system"""
    Base = declarative_base()
    
    class AuditRecord(Base):
        __tablename__ = 'audit_records'
        
        event_id = Column(String, primary_key=True)
        timestamp = Column(DateTime, nullable=False, index=True)
        event_type = Column(String, nullable=False, index=True)
        severity = Column(String, nullable=False)
        user_id = Column(String, nullable=True, index=True)
        session_id = Column(String, nullable=True, index=True)
        source_ip = Column(String, nullable=True)
        user_agent = Column(Text, nullable=True)
        action = Column(String, nullable=False)
        resource = Column(String, nullable=False, index=True)
        resource_type = Column(String, nullable=False)
        outcome = Column(String, nullable=False)
        details = Column(JSON, nullable=False)
        sensitive_data_accessed = Column(Boolean, nullable=False, default=False)
        data_classification = Column(String, nullable=True)
        compliance_frameworks = Column(JSON, nullable=False)
        retention_period = Column(Integer, nullable=False)
        digital_signature = Column(Text, nullable=True)
        status = Column(String, nullable=False, default="active")
        hash_chain_value = Column(String, nullable=True)
        
    class AuditIntegrityLog(Base):
        __tablename__ = 'audit_integrity_logs'
        
        check_id = Column(String, primary_key=True)
        timestamp = Column(DateTime, nullable=False)
        total_records_checked = Column(Integer, nullable=False)
        integrity_violations = Column(Integer, nullable=False)
        tampered_records = Column(JSON, nullable=False)
        missing_records = Column(JSON, nullable=False)
        signature_failures = Column(JSON, nullable=False)
        overall_integrity = Column(Boolean, nullable=False)
        confidence_score = Column(Float, nullable=False)
        
    class AuditConfiguration(Base):
        __tablename__ = 'audit_configuration'
        
        config_id = Column(String, primary_key=True)
        config_name = Column(String, nullable=False)
        event_types = Column(JSON, nullable=False)
        retention_policies = Column(JSON, nullable=False)
        integrity_check_frequency = Column(String, nullable=False)
        encryption_enabled = Column(Boolean, nullable=False)
        digital_signatures_enabled = Column(Boolean, nullable=False)
        real_time_alerting = Column(Boolean, nullable=False)
        created_at = Column(DateTime, default=datetime.utcnow)
        updated_at = Column(DateTime, default=datetime.utcnow)

class AuditTrailSystem:
    """
    Comprehensive audit trail system for AI/ML compliance
    Provides tamper-evident logging with digital signatures and integrity verification
    """
    
    def __init__(
        self,
        database_url: str = "postgresql://localhost/isectech_audit_trail",
        redis_url: str = "redis://localhost:6379/6",
        encryption_key: Optional[bytes] = None,
        signing_key: Optional[rsa.RSAPrivateKey] = None
    ):
        """Initialize audit trail system"""
        self.database_url = database_url
        self.redis_url = redis_url
        self.encryption_key = encryption_key or Fernet.generate_key()
        self.cipher_suite = Fernet(self.encryption_key)
        
        # Digital signature keys for tamper detection
        self.signing_key = signing_key or rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.signing_key.public_key()
        
        # Database setup
        self.engine = create_engine(database_url)
        AuditTrailDB.Base.metadata.create_all(self.engine)
        self.SessionLocal = sessionmaker(bind=self.engine)
        
        # Redis for real-time access
        self.redis_pool = None
        
        # Hash chain for tamper detection
        self.last_hash = self._get_genesis_hash()
        
        # Default retention policies
        self.retention_policies = {
            AuditEventType.USER_AUTHENTICATION: 365,  # 1 year
            AuditEventType.DATA_ACCESS: 2555,         # 7 years
            AuditEventType.MODEL_TRAINING: 2555,      # 7 years
            AuditEventType.SECURITY_EVENT: 2555,      # 7 years
            AuditEventType.COMPLIANCE_EVENT: 2555,    # 7 years
        }
        
        logger.info("Audit Trail System initialized with digital signatures and integrity checking")

    async def initialize_redis(self) -> None:
        """Initialize Redis connection"""
        if not self.redis_pool:
            self.redis_pool = aioredis.from_url(
                self.redis_url,
                encoding="utf-8",
                decode_responses=True,
                max_connections=10
            )

    def _get_genesis_hash(self) -> str:
        """Get genesis hash for hash chain"""
        return hashlib.sha256("AUDIT_TRAIL_GENESIS".encode()).hexdigest()

    def _calculate_hash_chain_value(self, event: AuditEvent, previous_hash: str) -> str:
        """Calculate hash chain value for tamper detection"""
        event_data = f"{event.event_id}{event.timestamp.isoformat()}{event.user_id}{event.action}{previous_hash}"
        return hashlib.sha256(event_data.encode()).hexdigest()

    def _sign_audit_record(self, event: AuditEvent) -> str:
        """Generate digital signature for audit record"""
        try:
            # Create signature payload
            signature_data = f"{event.event_id}{event.timestamp.isoformat()}{event.action}{event.resource}"
            signature_bytes = signature_data.encode()
            
            # Sign with private key
            signature = self.signing_key.sign(
                signature_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            return base64.b64encode(signature).decode()
            
        except Exception as e:
            logger.error(f"Error signing audit record: {str(e)}")
            return ""

    def _verify_signature(self, event: AuditEvent, signature: str) -> bool:
        """Verify digital signature of audit record"""
        try:
            # Reconstruct signature data
            signature_data = f"{event.event_id}{event.timestamp.isoformat()}{event.action}{event.resource}"
            signature_bytes = signature_data.encode()
            
            # Decode signature
            signature_decoded = base64.b64decode(signature.encode())
            
            # Verify with public key
            self.public_key.verify(
                signature_decoded,
                signature_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            return True
            
        except Exception as e:
            logger.debug(f"Signature verification failed: {str(e)}")
            return False

    async def log_audit_event(
        self,
        event_type: AuditEventType,
        action: str,
        resource: str,
        resource_type: str,
        outcome: str = "success",
        user_id: Optional[str] = None,
        session_id: Optional[str] = None,
        source_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        severity: AuditSeverity = AuditSeverity.INFO,
        sensitive_data_accessed: bool = False,
        data_classification: Optional[str] = None,
        compliance_frameworks: List[str] = None
    ) -> str:
        """
        Log an audit event with comprehensive tracking
        
        Args:
            event_type: Type of event being logged
            action: Action that was performed
            resource: Resource that was accessed/modified
            resource_type: Type of resource
            outcome: Result of the action
            user_id: User who performed the action
            session_id: Session identifier
            source_ip: Source IP address
            user_agent: User agent string
            details: Additional event details
            severity: Event severity level
            sensitive_data_accessed: Whether sensitive data was accessed
            data_classification: Classification of data involved
            compliance_frameworks: Applicable compliance frameworks
            
        Returns:
            Event ID of the logged audit record
        """
        event_id = str(uuid.uuid4())
        timestamp = datetime.utcnow()
        
        if details is None:
            details = {}
        if compliance_frameworks is None:
            compliance_frameworks = []
        
        # Determine retention period
        retention_period = self.retention_policies.get(event_type, 365)
        
        # Create audit event
        event = AuditEvent(
            event_id=event_id,
            timestamp=timestamp,
            event_type=event_type,
            severity=severity,
            user_id=user_id,
            session_id=session_id,
            source_ip=source_ip,
            user_agent=user_agent,
            action=action,
            resource=resource,
            resource_type=resource_type,
            outcome=outcome,
            details=details,
            sensitive_data_accessed=sensitive_data_accessed,
            data_classification=data_classification,
            compliance_frameworks=compliance_frameworks,
            retention_period=retention_period,
            digital_signature=""
        )
        
        # Generate digital signature
        event.digital_signature = self._sign_audit_record(event)
        
        # Calculate hash chain value
        hash_chain_value = self._calculate_hash_chain_value(event, self.last_hash)
        self.last_hash = hash_chain_value
        
        # Store in database
        db = self.SessionLocal()
        try:
            # Encrypt sensitive details if needed
            encrypted_details = details
            if sensitive_data_accessed and details:
                sensitive_keys = ['password', 'token', 'key', 'secret', 'personal']
                has_sensitive = any(key in str(details).lower() for key in sensitive_keys)
                
                if has_sensitive:
                    encrypted_details = self._encrypt_details(details)
            
            db_record = AuditTrailDB.AuditRecord(
                event_id=event_id,
                timestamp=timestamp,
                event_type=event_type.value,
                severity=severity.value,
                user_id=user_id,
                session_id=session_id,
                source_ip=source_ip,
                user_agent=user_agent,
                action=action,
                resource=resource,
                resource_type=resource_type,
                outcome=outcome,
                details=encrypted_details,
                sensitive_data_accessed=sensitive_data_accessed,
                data_classification=data_classification,
                compliance_frameworks=compliance_frameworks,
                retention_period=retention_period,
                digital_signature=event.digital_signature,
                hash_chain_value=hash_chain_value
            )
            
            db.add(db_record)
            db.commit()
            
            # Cache recent events for real-time monitoring
            await self.initialize_redis()
            await self._cache_recent_event(event)
            
            # Send real-time alerts for critical events
            if severity == AuditSeverity.CRITICAL:
                await self._send_critical_audit_alert(event)
            
            logger.info(f"Audit event logged: {event_id} ({event_type.value})")
            return event_id
            
        except Exception as e:
            db.rollback()
            logger.error(f"Error logging audit event: {str(e)}")
            raise
        finally:
            db.close()

    def _encrypt_details(self, details: Dict[str, Any]) -> Dict[str, Any]:
        """Encrypt sensitive details in audit record"""
        encrypted_details = {}
        sensitive_keys = ['password', 'token', 'key', 'secret', 'personal']
        
        for key, value in details.items():
            if any(sk in key.lower() for sk in sensitive_keys):
                # Encrypt sensitive values
                encrypted_value = self.cipher_suite.encrypt(str(value).encode())
                encrypted_details[key] = f"ENCRYPTED:{encrypted_value.decode()}"
            else:
                encrypted_details[key] = value
        
        return encrypted_details

    def _decrypt_details(self, details: Dict[str, Any]) -> Dict[str, Any]:
        """Decrypt sensitive details from audit record"""
        decrypted_details = {}
        
        for key, value in details.items():
            if isinstance(value, str) and value.startswith("ENCRYPTED:"):
                # Decrypt encrypted values
                encrypted_data = value[10:]  # Remove "ENCRYPTED:" prefix
                try:
                    decrypted_value = self.cipher_suite.decrypt(encrypted_data.encode())
                    decrypted_details[key] = decrypted_value.decode()
                except Exception as e:
                    logger.error(f"Error decrypting audit detail: {str(e)}")
                    decrypted_details[key] = "DECRYPTION_FAILED"
            else:
                decrypted_details[key] = value
        
        return decrypted_details

    async def _cache_recent_event(self, event: AuditEvent) -> None:
        """Cache recent events for real-time monitoring"""
        try:
            # Cache by user
            if event.user_id:
                user_cache_key = f"audit:user:{event.user_id}:recent"
                recent_events = await self.redis_pool.get(user_cache_key)
                
                if recent_events:
                    events = json.loads(recent_events)
                else:
                    events = []
                
                events.append({
                    'event_id': event.event_id,
                    'timestamp': event.timestamp.isoformat(),
                    'action': event.action,
                    'resource': event.resource,
                    'outcome': event.outcome
                })
                
                # Keep only last 50 events
                events = events[-50:]
                
                await self.redis_pool.setex(
                    user_cache_key,
                    3600,  # 1 hour
                    json.dumps(events)
                )
            
            # Cache by event type
            type_cache_key = f"audit:type:{event.event_type.value}:recent"
            await self.redis_pool.lpush(type_cache_key, event.event_id)
            await self.redis_pool.ltrim(type_cache_key, 0, 99)  # Keep last 100
            await self.redis_pool.expire(type_cache_key, 3600)  # 1 hour
            
        except Exception as e:
            logger.error(f"Error caching audit event: {str(e)}")

    async def _send_critical_audit_alert(self, event: AuditEvent) -> None:
        """Send alert for critical audit events"""
        # In production, this would integrate with alerting systems
        logger.critical(
            f"CRITICAL AUDIT EVENT: {event.event_id} - "
            f"User: {event.user_id}, Action: {event.action}, Resource: {event.resource}"
        )

    async def query_audit_trail(self, query: AuditQuery) -> List[Dict[str, Any]]:
        """
        Query audit trail with comprehensive filtering
        
        Args:
            query: Query parameters
            
        Returns:
            List of matching audit records
        """
        db = self.SessionLocal()
        try:
            # Build query
            db_query = db.query(AuditTrailDB.AuditRecord).filter(
                AuditTrailDB.AuditRecord.status == "active"
            )
            
            # Apply filters
            if query.start_date:
                db_query = db_query.filter(AuditTrailDB.AuditRecord.timestamp >= query.start_date)
            
            if query.end_date:
                db_query = db_query.filter(AuditTrailDB.AuditRecord.timestamp <= query.end_date)
            
            if query.user_id:
                db_query = db_query.filter(AuditTrailDB.AuditRecord.user_id == query.user_id)
            
            if query.event_types:
                event_type_values = [et.value for et in query.event_types]
                db_query = db_query.filter(AuditTrailDB.AuditRecord.event_type.in_(event_type_values))
            
            if query.severities:
                severity_values = [s.value for s in query.severities]
                db_query = db_query.filter(AuditTrailDB.AuditRecord.severity.in_(severity_values))
            
            if query.resource:
                db_query = db_query.filter(AuditTrailDB.AuditRecord.resource == query.resource)
            
            if query.outcome:
                db_query = db_query.filter(AuditTrailDB.AuditRecord.outcome == query.outcome)
            
            if query.sensitive_data_only:
                db_query = db_query.filter(AuditTrailDB.AuditRecord.sensitive_data_accessed == True)
            
            # Apply pagination
            db_query = db_query.order_by(AuditTrailDB.AuditRecord.timestamp.desc())
            db_query = db_query.offset(query.offset).limit(query.limit)
            
            # Execute query
            records = db_query.all()
            
            # Convert to response format
            results = []
            for record in records:
                event_data = {
                    'event_id': record.event_id,
                    'timestamp': record.timestamp.isoformat(),
                    'event_type': record.event_type,
                    'severity': record.severity,
                    'user_id': record.user_id,
                    'session_id': record.session_id,
                    'source_ip': record.source_ip,
                    'action': record.action,
                    'resource': record.resource,
                    'resource_type': record.resource_type,
                    'outcome': record.outcome,
                    'details': self._decrypt_details(record.details) if record.sensitive_data_accessed else record.details,
                    'sensitive_data_accessed': record.sensitive_data_accessed,
                    'data_classification': record.data_classification,
                    'compliance_frameworks': record.compliance_frameworks,
                    'signature_verified': self._verify_signature(
                        AuditEvent(
                            event_id=record.event_id,
                            timestamp=record.timestamp,
                            event_type=AuditEventType(record.event_type),
                            severity=AuditSeverity(record.severity),
                            user_id=record.user_id,
                            session_id=record.session_id,
                            source_ip=record.source_ip,
                            user_agent=record.user_agent,
                            action=record.action,
                            resource=record.resource,
                            resource_type=record.resource_type,
                            outcome=record.outcome,
                            details=record.details,
                            sensitive_data_accessed=record.sensitive_data_accessed,
                            data_classification=record.data_classification,
                            compliance_frameworks=record.compliance_frameworks,
                            retention_period=record.retention_period,
                            digital_signature=record.digital_signature
                        ),
                        record.digital_signature
                    ) if record.digital_signature else False
                }
                
                results.append(event_data)
            
            logger.info(f"Audit trail query returned {len(results)} records")
            return results
            
        except Exception as e:
            logger.error(f"Error querying audit trail: {str(e)}")
            raise
        finally:
            db.close()

    async def verify_audit_integrity(
        self,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None
    ) -> AuditIntegrityCheck:
        """
        Verify integrity of audit trail records
        
        Args:
            start_date: Start date for integrity check
            end_date: End date for integrity check
            
        Returns:
            Integrity check results
        """
        check_id = str(uuid.uuid4())
        timestamp = datetime.utcnow()
        
        if end_date is None:
            end_date = timestamp
        if start_date is None:
            start_date = end_date - timedelta(days=30)
        
        db = self.SessionLocal()
        try:
            # Get records to check
            records = db.query(AuditTrailDB.AuditRecord).filter(
                AuditTrailDB.AuditRecord.timestamp.between(start_date, end_date),
                AuditTrailDB.AuditRecord.status == "active"
            ).order_by(AuditTrailDB.AuditRecord.timestamp).all()
            
            total_records = len(records)
            tampered_records = []
            signature_failures = []
            missing_records = []
            
            # Check digital signatures
            for record in records:
                if record.digital_signature:
                    event = AuditEvent(
                        event_id=record.event_id,
                        timestamp=record.timestamp,
                        event_type=AuditEventType(record.event_type),
                        severity=AuditSeverity(record.severity),
                        user_id=record.user_id,
                        session_id=record.session_id,
                        source_ip=record.source_ip,
                        user_agent=record.user_agent,
                        action=record.action,
                        resource=record.resource,
                        resource_type=record.resource_type,
                        outcome=record.outcome,
                        details=record.details,
                        sensitive_data_accessed=record.sensitive_data_accessed,
                        data_classification=record.data_classification,
                        compliance_frameworks=record.compliance_frameworks,
                        retention_period=record.retention_period,
                        digital_signature=record.digital_signature
                    )
                    
                    if not self._verify_signature(event, record.digital_signature):
                        signature_failures.append(record.event_id)
            
            # Check hash chain integrity
            previous_hash = self._get_genesis_hash()
            for i, record in enumerate(records):
                event = AuditEvent(
                    event_id=record.event_id,
                    timestamp=record.timestamp,
                    event_type=AuditEventType(record.event_type),
                    severity=AuditSeverity(record.severity),
                    user_id=record.user_id,
                    session_id=record.session_id,
                    source_ip=record.source_ip,
                    user_agent=record.user_agent,
                    action=record.action,
                    resource=record.resource,
                    resource_type=record.resource_type,
                    outcome=record.outcome,
                    details=record.details,
                    sensitive_data_accessed=record.sensitive_data_accessed,
                    data_classification=record.data_classification,
                    compliance_frameworks=record.compliance_frameworks,
                    retention_period=record.retention_period,
                    digital_signature=record.digital_signature
                )
                
                expected_hash = self._calculate_hash_chain_value(event, previous_hash)
                
                if record.hash_chain_value != expected_hash:
                    tampered_records.append(record.event_id)
                
                previous_hash = record.hash_chain_value or expected_hash
            
            # Calculate integrity metrics
            integrity_violations = len(tampered_records) + len(signature_failures)
            overall_integrity = integrity_violations == 0
            confidence_score = max(0.0, 1.0 - (integrity_violations / max(1, total_records)))
            
            integrity_check = AuditIntegrityCheck(
                check_id=check_id,
                timestamp=timestamp,
                total_records_checked=total_records,
                integrity_violations=integrity_violations,
                tampered_records=tampered_records,
                missing_records=missing_records,
                signature_failures=signature_failures,
                overall_integrity=overall_integrity,
                confidence_score=confidence_score
            )
            
            # Store integrity check results
            db_check = AuditTrailDB.AuditIntegrityLog(
                check_id=check_id,
                timestamp=timestamp,
                total_records_checked=total_records,
                integrity_violations=integrity_violations,
                tampered_records=tampered_records,
                missing_records=missing_records,
                signature_failures=signature_failures,
                overall_integrity=overall_integrity,
                confidence_score=confidence_score
            )
            
            db.add(db_check)
            db.commit()
            
            logger.info(
                f"Audit integrity check completed: {check_id} - "
                f"{confidence_score:.2%} integrity confidence"
            )
            
            return integrity_check
            
        except Exception as e:
            db.rollback()
            logger.error(f"Error verifying audit integrity: {str(e)}")
            raise
        finally:
            db.close()

    async def generate_compliance_audit_report(
        self,
        compliance_framework: str,
        start_date: datetime,
        end_date: datetime
    ) -> Dict[str, Any]:
        """
        Generate compliance-specific audit report
        
        Args:
            compliance_framework: Framework to report on (HIPAA, PCI, SOC2, etc.)
            start_date: Report period start
            end_date: Report period end
            
        Returns:
            Comprehensive audit report
        """
        db = self.SessionLocal()
        try:
            # Query records for the compliance framework
            records = db.query(AuditTrailDB.AuditRecord).filter(
                AuditTrailDB.AuditRecord.timestamp.between(start_date, end_date),
                AuditTrailDB.AuditRecord.compliance_frameworks.contains([compliance_framework]),
                AuditTrailDB.AuditRecord.status == "active"
            ).all()
            
            # Run integrity check for the period
            integrity_check = await self.verify_audit_integrity(start_date, end_date)
            
            # Analyze audit events
            event_analysis = self._analyze_audit_events(records)
            
            # Security event analysis
            security_analysis = self._analyze_security_events(records)
            
            # User activity analysis
            user_analysis = self._analyze_user_activity(records)
            
            # Generate report
            report = {
                'compliance_framework': compliance_framework.upper(),
                'report_metadata': {
                    'report_id': str(uuid.uuid4()),
                    'generated_at': datetime.utcnow().isoformat(),
                    'period_start': start_date.isoformat(),
                    'period_end': end_date.isoformat(),
                    'total_events': len(records)
                },
                'integrity_assessment': {
                    'overall_integrity': integrity_check.overall_integrity,
                    'confidence_score': integrity_check.confidence_score,
                    'records_checked': integrity_check.total_records_checked,
                    'violations_detected': integrity_check.integrity_violations,
                    'tampered_records': len(integrity_check.tampered_records),
                    'signature_failures': len(integrity_check.signature_failures)
                },
                'event_analysis': event_analysis,
                'security_analysis': security_analysis,
                'user_activity_analysis': user_analysis,
                'compliance_metrics': {
                    'sensitive_data_events': len([r for r in records if r.sensitive_data_accessed]),
                    'failed_operations': len([r for r in records if r.outcome == 'failure']),
                    'critical_events': len([r for r in records if r.severity == 'critical']),
                    'unique_users': len(set(r.user_id for r in records if r.user_id)),
                    'unique_resources': len(set(r.resource for r in records))
                },
                'recommendations': self._generate_audit_recommendations(
                    records, integrity_check, compliance_framework
                )
            }
            
            logger.info(
                f"Compliance audit report generated for {compliance_framework}: "
                f"{len(records)} events analyzed"
            )
            
            return report
            
        except Exception as e:
            logger.error(f"Error generating compliance audit report: {str(e)}")
            raise
        finally:
            db.close()

    def _analyze_audit_events(self, records: List[AuditTrailDB.AuditRecord]) -> Dict[str, Any]:
        """Analyze audit events for patterns and statistics"""
        if not records:
            return {'no_data': True}
        
        # Event type distribution
        event_type_counts = {}
        severity_counts = {}
        outcome_counts = {}
        
        for record in records:
            event_type_counts[record.event_type] = event_type_counts.get(record.event_type, 0) + 1
            severity_counts[record.severity] = severity_counts.get(record.severity, 0) + 1
            outcome_counts[record.outcome] = outcome_counts.get(record.outcome, 0) + 1
        
        # Time-based analysis
        records_by_hour = {}
        for record in records:
            hour = record.timestamp.hour
            records_by_hour[hour] = records_by_hour.get(hour, 0) + 1
        
        return {
            'event_type_distribution': event_type_counts,
            'severity_distribution': severity_counts,
            'outcome_distribution': outcome_counts,
            'peak_activity_hours': sorted(records_by_hour.items(), key=lambda x: x[1], reverse=True)[:3],
            'total_events': len(records)
        }

    def _analyze_security_events(self, records: List[AuditTrailDB.AuditRecord]) -> Dict[str, Any]:
        """Analyze security-related events"""
        security_events = [r for r in records if r.event_type == 'security_event']
        
        if not security_events:
            return {'no_security_events': True}
        
        # Failed authentication analysis
        failed_auth = [r for r in records if 'authentication' in r.action and r.outcome == 'failure']
        
        # Suspicious IP analysis
        ip_counts = {}
        for record in records:
            if record.source_ip:
                ip_counts[record.source_ip] = ip_counts.get(record.source_ip, 0) + 1
        
        suspicious_ips = [(ip, count) for ip, count in ip_counts.items() if count > 100]
        
        return {
            'total_security_events': len(security_events),
            'failed_authentications': len(failed_auth),
            'suspicious_ip_addresses': suspicious_ips,
            'critical_security_events': len([r for r in security_events if r.severity == 'critical'])
        }

    def _analyze_user_activity(self, records: List[AuditTrailDB.AuditRecord]) -> Dict[str, Any]:
        """Analyze user activity patterns"""
        user_activity = {}
        
        for record in records:
            if record.user_id:
                if record.user_id not in user_activity:
                    user_activity[record.user_id] = {
                        'total_events': 0,
                        'failed_events': 0,
                        'sensitive_data_access': 0,
                        'last_activity': record.timestamp
                    }
                
                user_activity[record.user_id]['total_events'] += 1
                
                if record.outcome == 'failure':
                    user_activity[record.user_id]['failed_events'] += 1
                
                if record.sensitive_data_accessed:
                    user_activity[record.user_id]['sensitive_data_access'] += 1
                
                if record.timestamp > user_activity[record.user_id]['last_activity']:
                    user_activity[record.user_id]['last_activity'] = record.timestamp
        
        # Find top users by activity
        top_users = sorted(
            user_activity.items(),
            key=lambda x: x[1]['total_events'],
            reverse=True
        )[:10]
        
        return {
            'total_unique_users': len(user_activity),
            'top_active_users': [(user, data['total_events']) for user, data in top_users],
            'users_with_failures': len([u for u in user_activity.values() if u['failed_events'] > 0]),
            'users_accessing_sensitive_data': len([u for u in user_activity.values() if u['sensitive_data_access'] > 0])
        }

    def _generate_audit_recommendations(
        self,
        records: List[AuditTrailDB.AuditRecord],
        integrity_check: AuditIntegrityCheck,
        compliance_framework: str
    ) -> List[str]:
        """Generate audit improvement recommendations"""
        recommendations = []
        
        # Integrity recommendations
        if not integrity_check.overall_integrity:
            recommendations.append("URGENT: Investigate audit trail integrity violations immediately")
            recommendations.append("Review access controls for audit logging system")
        
        # Security recommendations
        failed_events = [r for r in records if r.outcome == 'failure']
        if len(failed_events) > len(records) * 0.05:  # >5% failure rate
            recommendations.append("High failure rate detected - review security controls")
        
        critical_events = [r for r in records if r.severity == 'critical']
        if critical_events:
            recommendations.append(f"Review {len(critical_events)} critical security events")
        
        # Compliance-specific recommendations
        if compliance_framework.upper() == 'HIPAA':
            phi_events = [r for r in records if r.sensitive_data_accessed]
            if phi_events:
                recommendations.append("Review all PHI access events for necessity and authorization")
        
        elif compliance_framework.upper() == 'PCI':
            recommendations.append("Ensure cardholder data access is properly logged and monitored")
        
        # General recommendations
        if not recommendations:
            recommendations.append("Audit trail appears healthy - continue current monitoring practices")
        
        return recommendations

# Convenience functions for AI/ML integration
async def setup_ai_ml_audit_trail(
    audit_system: AuditTrailSystem,
    model_name: str
) -> str:
    """Setup audit trail for AI/ML model"""
    
    # Log model setup
    event_id = await audit_system.log_audit_event(
        event_type=AuditEventType.SYSTEM_EVENT,
        action="model_audit_setup",
        resource=model_name,
        resource_type="ai_ml_model",
        outcome="success",
        user_id="system",
        details={
            'model_name': model_name,
            'audit_features': ['digital_signatures', 'hash_chain', 'tamper_detection']
        },
        compliance_frameworks=['HIPAA', 'PCI', 'SOC2']
    )
    
    logger.info(f"Audit trail configured for AI/ML model: {model_name}")
    return event_id

if __name__ == "__main__":
    # Example usage and testing
    async def test_audit_trail_system():
        audit_system = AuditTrailSystem()
        
        # Setup audit trail for AI model
        setup_event = await setup_ai_ml_audit_trail(audit_system, "threat-detection-model")
        print(f"Audit trail setup: {setup_event}")
        
        # Log various audit events
        auth_event = await audit_system.log_audit_event(
            event_type=AuditEventType.USER_AUTHENTICATION,
            action="user_login",
            resource="ai_ml_dashboard",
            resource_type="web_application",
            outcome="success",
            user_id="data_scientist_1",
            source_ip="192.168.1.100",
            details={'authentication_method': 'mfa'},
            compliance_frameworks=['HIPAA', 'SOC2']
        )
        
        data_access_event = await audit_system.log_audit_event(
            event_type=AuditEventType.DATA_ACCESS,
            action="training_data_access",
            resource="phi_training_dataset",
            resource_type="dataset",
            outcome="success",
            user_id="data_scientist_1",
            sensitive_data_accessed=True,
            data_classification="PHI",
            details={'records_accessed': 1000, 'purpose': 'model_training'},
            compliance_frameworks=['HIPAA']
        )
        
        # Query audit trail
        query = AuditQuery(
            start_date=datetime.utcnow() - timedelta(hours=1),
            user_id="data_scientist_1",
            limit=10
        )
        
        results = await audit_system.query_audit_trail(query)
        print(f"Audit query returned {len(results)} records")
        
        # Verify integrity
        integrity_check = await audit_system.verify_audit_integrity()
        print(f"Audit integrity: {integrity_check.confidence_score:.2%} confidence")
        
        # Generate compliance report
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=1)
        
        hipaa_report = await audit_system.generate_compliance_audit_report(
            'HIPAA', start_date, end_date
        )
        print(f"HIPAA audit report generated with {hipaa_report['report_metadata']['total_events']} events")
    
    # Run test
    asyncio.run(test_audit_trail_system())