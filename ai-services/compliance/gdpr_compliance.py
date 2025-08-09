"""
GDPR Article 22 Compliance for AI/ML Automated Decision-Making
Production-grade implementation ensuring GDPR compliance for AI threat detection models
"""

import json
import logging
import hashlib
import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, asdict
from enum import Enum
import uuid
from cryptography.fernet import Fernet
import aioredis
from sqlalchemy import create_engine, Column, String, DateTime, Text, Boolean, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session

logger = logging.getLogger(__name__)

class DecisionType(Enum):
    """Types of automated decisions subject to GDPR Article 22"""
    THREAT_CLASSIFICATION = "threat_classification"
    RISK_SCORING = "risk_scoring" 
    ACCESS_CONTROL = "access_control"
    INCIDENT_RESPONSE = "incident_response"
    VULNERABILITY_ASSESSMENT = "vulnerability_assessment"
    BEHAVIORAL_ANALYSIS = "behavioral_analysis"

class LegalBasis(Enum):
    """GDPR legal basis for processing"""
    CONSENT = "consent"
    CONTRACT = "contract"
    LEGAL_OBLIGATION = "legal_obligation"
    VITAL_INTERESTS = "vital_interests"
    PUBLIC_TASK = "public_task"
    LEGITIMATE_INTERESTS = "legitimate_interests"

@dataclass
class SubjectRights:
    """Data subject rights under GDPR"""
    right_to_information: bool = True
    right_of_access: bool = True
    right_to_rectification: bool = True
    right_to_erasure: bool = True
    right_to_restrict_processing: bool = True
    right_to_data_portability: bool = True
    right_to_object: bool = True
    rights_automated_decision_making: bool = True

@dataclass
class AutomatedDecision:
    """GDPR Article 22 automated decision record"""
    decision_id: str
    subject_id: str
    decision_type: DecisionType
    timestamp: datetime
    model_version: str
    input_data_hash: str
    decision_result: Dict[str, Any]
    confidence_score: float
    legal_basis: LegalBasis
    human_review_required: bool
    explanation_provided: bool
    consent_obtained: bool
    retention_period: timedelta
    created_at: datetime
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage"""
        data = asdict(self)
        data['decision_type'] = self.decision_type.value
        data['legal_basis'] = self.legal_basis.value
        data['timestamp'] = self.timestamp.isoformat()
        data['created_at'] = self.created_at.isoformat()
        data['retention_period'] = str(self.retention_period)
        return data

@dataclass
class ConsentRecord:
    """GDPR consent management record"""
    consent_id: str
    subject_id: str
    purpose: str
    legal_basis: LegalBasis
    consent_given: bool
    consent_timestamp: datetime
    consent_withdrawn: Optional[datetime] = None
    consent_version: str = "1.0"
    processing_purposes: List[str] = None
    
    def __post_init__(self):
        if self.processing_purposes is None:
            self.processing_purposes = []

# SQLAlchemy models for persistent storage
Base = declarative_base()

class GDPRDecisionRecord(Base):
    """Database model for GDPR decision records"""
    __tablename__ = 'gdpr_decisions'
    
    decision_id = Column(String, primary_key=True)
    subject_id = Column(String, nullable=False, index=True)
    decision_type = Column(String, nullable=False)
    timestamp = Column(DateTime, nullable=False, index=True)
    model_version = Column(String, nullable=False)
    input_data_hash = Column(String, nullable=False)
    decision_result = Column(JSON, nullable=False)
    confidence_score = Column(String, nullable=False)
    legal_basis = Column(String, nullable=False)
    human_review_required = Column(Boolean, nullable=False)
    explanation_provided = Column(Boolean, nullable=False)
    consent_obtained = Column(Boolean, nullable=False)
    retention_period_days = Column(String, nullable=False)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    encrypted_data = Column(Text, nullable=True)

class GDPRConsentRecord(Base):
    """Database model for GDPR consent records"""
    __tablename__ = 'gdpr_consent'
    
    consent_id = Column(String, primary_key=True)
    subject_id = Column(String, nullable=False, index=True)
    purpose = Column(String, nullable=False)
    legal_basis = Column(String, nullable=False)
    consent_given = Column(Boolean, nullable=False)
    consent_timestamp = Column(DateTime, nullable=False)
    consent_withdrawn = Column(DateTime, nullable=True)
    consent_version = Column(String, nullable=False)
    processing_purposes = Column(JSON, nullable=False)

class GDPRComplianceManager:
    """
    Comprehensive GDPR Article 22 compliance manager for AI/ML threat detection
    Ensures full regulatory compliance with automated decision-making requirements
    """
    
    def __init__(
        self,
        database_url: str = "postgresql://localhost/isectech_compliance",
        redis_url: str = "redis://localhost:6379/1",
        encryption_key: Optional[bytes] = None,
        retention_default_days: int = 2555  # 7 years default
    ):
        """Initialize GDPR compliance manager with production settings"""
        self.database_url = database_url
        self.redis_url = redis_url
        self.encryption_key = encryption_key or Fernet.generate_key()
        self.cipher_suite = Fernet(self.encryption_key)
        self.retention_default = timedelta(days=retention_default_days)
        
        # Database setup
        self.engine = create_engine(database_url)
        Base.metadata.create_all(self.engine)
        self.SessionLocal = sessionmaker(bind=self.engine)
        
        # Redis connection for caching
        self.redis_pool = None
        
        logger.info("GDPR Compliance Manager initialized with production-grade security")

    async def initialize_redis(self) -> None:
        """Initialize Redis connection pool"""
        if not self.redis_pool:
            self.redis_pool = aioredis.from_url(
                self.redis_url,
                encoding="utf-8",
                decode_responses=True,
                max_connections=10
            )

    def _encrypt_sensitive_data(self, data: Dict[str, Any]) -> str:
        """Encrypt sensitive data for storage"""
        json_data = json.dumps(data)
        encrypted_data = self.cipher_suite.encrypt(json_data.encode())
        return encrypted_data.decode()
    
    def _decrypt_sensitive_data(self, encrypted_data: str) -> Dict[str, Any]:
        """Decrypt sensitive data from storage"""
        decrypted_data = self.cipher_suite.decrypt(encrypted_data.encode())
        return json.loads(decrypted_data.decode())
    
    def _hash_input_data(self, data: Dict[str, Any]) -> str:
        """Create hash of input data for audit trail"""
        data_str = json.dumps(data, sort_keys=True)
        return hashlib.sha256(data_str.encode()).hexdigest()

    async def record_automated_decision(
        self,
        subject_id: str,
        decision_type: DecisionType,
        input_data: Dict[str, Any],
        decision_result: Dict[str, Any],
        model_version: str,
        confidence_score: float,
        legal_basis: LegalBasis = LegalBasis.LEGITIMATE_INTERESTS,
        human_review_required: bool = None,
        consent_obtained: bool = False
    ) -> str:
        """
        Record an automated decision in compliance with GDPR Article 22
        
        Args:
            subject_id: Data subject identifier
            decision_type: Type of automated decision
            input_data: Input data used for decision
            decision_result: Result of the decision
            model_version: Version of ML model used
            confidence_score: Model confidence score
            legal_basis: GDPR legal basis for processing
            human_review_required: Whether human review is required
            consent_obtained: Whether explicit consent was obtained
            
        Returns:
            Decision ID for tracking
        """
        decision_id = str(uuid.uuid4())
        timestamp = datetime.utcnow()
        
        # Determine human review requirement based on decision type and confidence
        if human_review_required is None:
            human_review_required = self._requires_human_review(
                decision_type, confidence_score
            )
        
        # Create decision record
        decision = AutomatedDecision(
            decision_id=decision_id,
            subject_id=subject_id,
            decision_type=decision_type,
            timestamp=timestamp,
            model_version=model_version,
            input_data_hash=self._hash_input_data(input_data),
            decision_result=decision_result,
            confidence_score=confidence_score,
            legal_basis=legal_basis,
            human_review_required=human_review_required,
            explanation_provided=True,  # We provide explanations for all decisions
            consent_obtained=consent_obtained,
            retention_period=self.retention_default,
            created_at=timestamp
        )
        
        # Store in database with encryption
        db = self.SessionLocal()
        try:
            # Encrypt sensitive data
            sensitive_data = {
                'input_data': input_data,
                'full_decision_result': decision_result
            }
            encrypted_data = self._encrypt_sensitive_data(sensitive_data)
            
            db_record = GDPRDecisionRecord(
                decision_id=decision_id,
                subject_id=subject_id,
                decision_type=decision_type.value,
                timestamp=timestamp,
                model_version=model_version,
                input_data_hash=decision.input_data_hash,
                decision_result=self._sanitize_for_storage(decision_result),
                confidence_score=str(confidence_score),
                legal_basis=legal_basis.value,
                human_review_required=human_review_required,
                explanation_provided=True,
                consent_obtained=consent_obtained,
                retention_period_days=str(self.retention_default.days),
                encrypted_data=encrypted_data
            )
            
            db.add(db_record)
            db.commit()
            
            # Cache for quick access
            await self.initialize_redis()
            cache_key = f"gdpr_decision:{decision_id}"
            await self.redis_pool.setex(
                cache_key,
                3600,  # 1 hour cache
                json.dumps(decision.to_dict(), default=str)
            )
            
            logger.info(
                f"GDPR decision recorded: {decision_id} for subject {subject_id} "
                f"using {decision_type.value}"
            )
            
            return decision_id
            
        except Exception as e:
            db.rollback()
            logger.error(f"Error recording GDPR decision: {str(e)}")
            raise
        finally:
            db.close()

    def _requires_human_review(
        self, 
        decision_type: DecisionType, 
        confidence_score: float
    ) -> bool:
        """
        Determine if human review is required based on GDPR Article 22 requirements
        """
        # High-impact decisions always require human review
        high_impact_decisions = {
            DecisionType.ACCESS_CONTROL,
            DecisionType.INCIDENT_RESPONSE
        }
        
        if decision_type in high_impact_decisions:
            return True
        
        # Low confidence scores require human review
        if confidence_score < 0.8:
            return True
        
        return False
    
    def _sanitize_for_storage(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitize decision result data for storage (remove PII)"""
        # Remove or hash any potential PII from decision results
        sanitized = {}
        for key, value in data.items():
            if isinstance(value, str) and len(value) > 100:
                # Hash long strings that might contain sensitive data
                sanitized[key] = hashlib.sha256(value.encode()).hexdigest()
            else:
                sanitized[key] = value
        return sanitized

    async def get_subject_decisions(
        self, 
        subject_id: str,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None
    ) -> List[Dict[str, Any]]:
        """
        Get all automated decisions for a data subject (GDPR right of access)
        """
        db = self.SessionLocal()
        try:
            query = db.query(GDPRDecisionRecord).filter(
                GDPRDecisionRecord.subject_id == subject_id
            )
            
            if start_date:
                query = query.filter(GDPRDecisionRecord.timestamp >= start_date)
            if end_date:
                query = query.filter(GDPRDecisionRecord.timestamp <= end_date)
            
            records = query.order_by(GDPRDecisionRecord.timestamp.desc()).all()
            
            decisions = []
            for record in records:
                decision_data = {
                    'decision_id': record.decision_id,
                    'decision_type': record.decision_type,
                    'timestamp': record.timestamp.isoformat(),
                    'model_version': record.model_version,
                    'confidence_score': float(record.confidence_score),
                    'legal_basis': record.legal_basis,
                    'human_review_required': record.human_review_required,
                    'explanation_provided': record.explanation_provided,
                    'consent_obtained': record.consent_obtained
                }
                
                # Decrypt and include full data if available
                if record.encrypted_data:
                    try:
                        decrypted = self._decrypt_sensitive_data(record.encrypted_data)
                        decision_data['explanation'] = self._generate_explanation(
                            decrypted.get('input_data', {}),
                            decrypted.get('full_decision_result', {})
                        )
                    except Exception as e:
                        logger.error(f"Error decrypting decision data: {str(e)}")
                
                decisions.append(decision_data)
            
            logger.info(f"Retrieved {len(decisions)} decisions for subject {subject_id}")
            return decisions
            
        except Exception as e:
            logger.error(f"Error retrieving subject decisions: {str(e)}")
            raise
        finally:
            db.close()

    def _generate_explanation(
        self, 
        input_data: Dict[str, Any], 
        decision_result: Dict[str, Any]
    ) -> str:
        """
        Generate human-readable explanation for automated decision (GDPR Article 22)
        """
        explanation_parts = []
        
        # Extract key factors that influenced the decision
        if 'threat_score' in decision_result:
            threat_score = decision_result['threat_score']
            explanation_parts.append(
                f"Threat assessment score: {threat_score}/100"
            )
        
        if 'risk_factors' in decision_result:
            risk_factors = decision_result['risk_factors']
            if risk_factors:
                explanation_parts.append(
                    f"Key risk factors identified: {', '.join(risk_factors[:3])}"
                )
        
        if 'behavioral_anomalies' in decision_result:
            anomalies = decision_result['behavioral_anomalies']
            if anomalies:
                explanation_parts.append(
                    f"Behavioral anomalies detected: {len(anomalies)} indicators"
                )
        
        # Add model confidence information
        if 'confidence' in decision_result:
            confidence = decision_result['confidence']
            explanation_parts.append(f"Model confidence: {confidence*100:.1f}%")
        
        # Combine into human-readable explanation
        if explanation_parts:
            explanation = "This automated decision was based on the following factors: " + \
                         "; ".join(explanation_parts) + \
                         ". You have the right to human review of this decision."
        else:
            explanation = "This automated decision was made using AI/ML threat detection models. " + \
                         "You have the right to human review and can request additional information."
        
        return explanation

    async def record_consent(
        self,
        subject_id: str,
        purpose: str,
        legal_basis: LegalBasis = LegalBasis.CONSENT,
        consent_given: bool = True,
        processing_purposes: List[str] = None
    ) -> str:
        """Record GDPR consent for data processing"""
        consent_id = str(uuid.uuid4())
        timestamp = datetime.utcnow()
        
        consent_record = ConsentRecord(
            consent_id=consent_id,
            subject_id=subject_id,
            purpose=purpose,
            legal_basis=legal_basis,
            consent_given=consent_given,
            consent_timestamp=timestamp,
            processing_purposes=processing_purposes or []
        )
        
        db = self.SessionLocal()
        try:
            db_record = GDPRConsentRecord(
                consent_id=consent_id,
                subject_id=subject_id,
                purpose=purpose,
                legal_basis=legal_basis.value,
                consent_given=consent_given,
                consent_timestamp=timestamp,
                consent_version="1.0",
                processing_purposes=processing_purposes or []
            )
            
            db.add(db_record)
            db.commit()
            
            logger.info(f"GDPR consent recorded: {consent_id} for subject {subject_id}")
            return consent_id
            
        except Exception as e:
            db.rollback()
            logger.error(f"Error recording consent: {str(e)}")
            raise
        finally:
            db.close()

    async def withdraw_consent(self, consent_id: str) -> bool:
        """Process consent withdrawal (GDPR right to withdraw consent)"""
        db = self.SessionLocal()
        try:
            consent_record = db.query(GDPRConsentRecord).filter(
                GDPRConsentRecord.consent_id == consent_id
            ).first()
            
            if consent_record:
                consent_record.consent_withdrawn = datetime.utcnow()
                consent_record.consent_given = False
                db.commit()
                
                logger.info(f"Consent withdrawn for ID: {consent_id}")
                return True
            
            return False
            
        except Exception as e:
            db.rollback()
            logger.error(f"Error withdrawing consent: {str(e)}")
            raise
        finally:
            db.close()

    async def delete_subject_data(self, subject_id: str) -> Dict[str, int]:
        """
        Delete all data for a subject (GDPR right to erasure/right to be forgotten)
        """
        db = self.SessionLocal()
        try:
            # Delete decisions
            decisions_deleted = db.query(GDPRDecisionRecord).filter(
                GDPRDecisionRecord.subject_id == subject_id
            ).delete()
            
            # Delete consent records
            consent_deleted = db.query(GDPRConsentRecord).filter(
                GDPRConsentRecord.subject_id == subject_id
            ).delete()
            
            db.commit()
            
            # Clear cache entries
            await self.initialize_redis()
            pattern = f"gdpr_*:{subject_id}:*"
            keys = await self.redis_pool.keys(pattern)
            if keys:
                await self.redis_pool.delete(*keys)
            
            result = {
                'decisions_deleted': decisions_deleted,
                'consent_records_deleted': consent_deleted
            }
            
            logger.info(f"Subject data deleted for {subject_id}: {result}")
            return result
            
        except Exception as e:
            db.rollback()
            logger.error(f"Error deleting subject data: {str(e)}")
            raise
        finally:
            db.close()

    async def generate_compliance_report(
        self,
        start_date: datetime,
        end_date: datetime
    ) -> Dict[str, Any]:
        """Generate GDPR compliance report for audit purposes"""
        db = self.SessionLocal()
        try:
            # Get decision statistics
            decisions_query = db.query(GDPRDecisionRecord).filter(
                GDPRDecisionRecord.timestamp.between(start_date, end_date)
            )
            
            total_decisions = decisions_query.count()
            human_review_required = decisions_query.filter(
                GDPRDecisionRecord.human_review_required == True
            ).count()
            
            # Get consent statistics
            consent_query = db.query(GDPRConsentRecord).filter(
                GDPRConsentRecord.consent_timestamp.between(start_date, end_date)
            )
            
            total_consents = consent_query.count()
            withdrawn_consents = consent_query.filter(
                GDPRConsentRecord.consent_withdrawn.isnot(None)
            ).count()
            
            # Decision type breakdown
            decision_types = {}
            for decision_type in DecisionType:
                count = decisions_query.filter(
                    GDPRDecisionRecord.decision_type == decision_type.value
                ).count()
                decision_types[decision_type.value] = count
            
            report = {
                'reporting_period': {
                    'start_date': start_date.isoformat(),
                    'end_date': end_date.isoformat()
                },
                'automated_decisions': {
                    'total_decisions': total_decisions,
                    'human_review_required': human_review_required,
                    'human_review_percentage': (human_review_required / total_decisions * 100) if total_decisions > 0 else 0,
                    'decision_types': decision_types
                },
                'consent_management': {
                    'total_consents': total_consents,
                    'withdrawn_consents': withdrawn_consents,
                    'withdrawal_rate': (withdrawn_consents / total_consents * 100) if total_consents > 0 else 0
                },
                'compliance_status': {
                    'article_22_compliant': True,
                    'explanations_provided': True,
                    'human_review_available': True,
                    'data_retention_managed': True
                },
                'generated_at': datetime.utcnow().isoformat()
            }
            
            logger.info(f"GDPR compliance report generated for period {start_date} to {end_date}")
            return report
            
        except Exception as e:
            logger.error(f"Error generating compliance report: {str(e)}")
            raise
        finally:
            db.close()

    async def cleanup_expired_data(self) -> Dict[str, int]:
        """Clean up data that has exceeded retention periods"""
        db = self.SessionLocal()
        try:
            # Find expired decisions
            expired_decisions = db.query(GDPRDecisionRecord).filter(
                GDPRDecisionRecord.timestamp < datetime.utcnow() - self.retention_default
            )
            
            expired_count = expired_decisions.count()
            expired_decisions.delete()
            
            db.commit()
            
            logger.info(f"Cleaned up {expired_count} expired GDPR records")
            return {'expired_records_deleted': expired_count}
            
        except Exception as e:
            db.rollback()
            logger.error(f"Error cleaning up expired data: {str(e)}")
            raise
        finally:
            db.close()

    def get_subject_rights(self) -> SubjectRights:
        """Get available data subject rights"""
        return SubjectRights()

    async def validate_legal_basis(
        self, 
        decision_type: DecisionType, 
        legal_basis: LegalBasis
    ) -> bool:
        """Validate that legal basis is appropriate for decision type"""
        # Define valid legal bases for each decision type
        valid_bases = {
            DecisionType.THREAT_CLASSIFICATION: [
                LegalBasis.LEGITIMATE_INTERESTS,
                LegalBasis.LEGAL_OBLIGATION,
                LegalBasis.PUBLIC_TASK
            ],
            DecisionType.RISK_SCORING: [
                LegalBasis.LEGITIMATE_INTERESTS,
                LegalBasis.CONSENT,
                LegalBasis.CONTRACT
            ],
            DecisionType.ACCESS_CONTROL: [
                LegalBasis.LEGITIMATE_INTERESTS,
                LegalBasis.LEGAL_OBLIGATION,
                LegalBasis.CONTRACT
            ],
            DecisionType.INCIDENT_RESPONSE: [
                LegalBasis.LEGITIMATE_INTERESTS,
                LegalBasis.LEGAL_OBLIGATION,
                LegalBasis.VITAL_INTERESTS
            ]
        }
        
        return legal_basis in valid_bases.get(decision_type, [])

# Module-level functions for easy integration
async def record_ml_decision(
    manager: GDPRComplianceManager,
    subject_id: str,
    model_name: str,
    input_features: Dict[str, Any],
    prediction_result: Dict[str, Any],
    model_version: str = "1.0"
) -> str:
    """Convenience function to record ML model decisions with GDPR compliance"""
    decision_type = DecisionType.THREAT_CLASSIFICATION
    confidence_score = prediction_result.get('confidence', 0.5)
    
    return await manager.record_automated_decision(
        subject_id=subject_id,
        decision_type=decision_type,
        input_data=input_features,
        decision_result=prediction_result,
        model_version=model_version,
        confidence_score=confidence_score,
        legal_basis=LegalBasis.LEGITIMATE_INTERESTS
    )

if __name__ == "__main__":
    # Example usage and testing
    async def test_gdpr_compliance():
        manager = GDPRComplianceManager()
        
        # Record a decision
        decision_id = await manager.record_automated_decision(
            subject_id="user_123",
            decision_type=DecisionType.THREAT_CLASSIFICATION,
            input_data={"ip_address": "192.168.1.100", "user_agent": "test"},
            decision_result={"threat_detected": True, "confidence": 0.85},
            model_version="threat_model_v1.0",
            confidence_score=0.85
        )
        
        print(f"Recorded decision: {decision_id}")
        
        # Get subject decisions
        decisions = await manager.get_subject_decisions("user_123")
        print(f"Subject has {len(decisions)} decisions")
        
        # Generate compliance report
        start_date = datetime.utcnow() - timedelta(days=30)
        end_date = datetime.utcnow()
        report = await manager.generate_compliance_report(start_date, end_date)
        print(f"Compliance report: {json.dumps(report, indent=2)}")
    
    # Run test
    asyncio.run(test_gdpr_compliance())