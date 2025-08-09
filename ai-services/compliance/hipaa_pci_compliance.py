"""
HIPAA/PCI DSS Compliance Framework for AI/ML Systems
Production-grade compliance management for healthcare and payment data protection
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
import re

logger = logging.getLogger(__name__)

class ComplianceFramework(Enum):
    """Supported compliance frameworks"""
    HIPAA = "hipaa"
    PCI_DSS = "pci_dss"

class DataClassification(Enum):
    """Data classification levels"""
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"
    PHI = "phi"  # Protected Health Information
    PII = "pii"  # Personally Identifiable Information
    CHD = "chd"  # Cardholder Data

class ViolationSeverity(Enum):
    """Compliance violation severity"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class ComplianceRequirement:
    """Compliance requirement definition"""
    requirement_id: str
    framework: ComplianceFramework
    title: str
    description: str
    control_objective: str
    implementation_guidance: str
    testing_procedures: List[str]
    data_types: List[DataClassification]
    responsible_party: str
    frequency: str
    
    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data['framework'] = self.framework.value
        data['data_types'] = [dt.value for dt in self.data_types]
        return data

@dataclass
class ComplianceViolation:
    """Compliance violation record"""
    violation_id: str
    requirement_id: str
    framework: ComplianceFramework
    severity: ViolationSeverity
    detected_at: datetime
    description: str
    affected_systems: List[str]
    data_exposure_risk: str
    remediation_steps: List[str]
    status: str  # "open", "in_progress", "resolved", "false_positive"
    resolved_at: Optional[datetime]
    
    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data['framework'] = self.framework.value
        data['severity'] = self.severity.value
        data['detected_at'] = self.detected_at.isoformat()
        data['resolved_at'] = self.resolved_at.isoformat() if self.resolved_at else None
        return data

@dataclass
class DataInventoryItem:
    """Data inventory item for compliance tracking"""
    item_id: str
    data_type: DataClassification
    location: str
    description: str
    retention_period: int  # days
    encryption_status: str
    access_controls: List[str]
    processing_purpose: str
    data_subjects: int
    last_accessed: datetime
    
    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data['data_type'] = self.data_type.value
        data['last_accessed'] = self.last_accessed.isoformat()
        return data

class ComplianceDB:
    """Database models for HIPAA/PCI DSS compliance"""
    Base = declarative_base()
    
    class RequirementRecord(Base):
        __tablename__ = 'compliance_requirements'
        
        requirement_id = Column(String, primary_key=True)
        framework = Column(String, nullable=False)
        title = Column(String, nullable=False)
        description = Column(Text, nullable=False)
        control_objective = Column(Text, nullable=False)
        implementation_guidance = Column(Text, nullable=False)
        testing_procedures = Column(JSON, nullable=False)
        data_types = Column(JSON, nullable=False)
        responsible_party = Column(String, nullable=False)
        frequency = Column(String, nullable=False)
        active = Column(Boolean, default=True)
        
    class ViolationRecord(Base):
        __tablename__ = 'compliance_violations'
        
        violation_id = Column(String, primary_key=True)
        requirement_id = Column(String, nullable=False, index=True)
        framework = Column(String, nullable=False)
        severity = Column(String, nullable=False)
        detected_at = Column(DateTime, nullable=False)
        description = Column(Text, nullable=False)
        affected_systems = Column(JSON, nullable=False)
        data_exposure_risk = Column(String, nullable=False)
        remediation_steps = Column(JSON, nullable=False)
        status = Column(String, nullable=False, default="open")
        resolved_at = Column(DateTime, nullable=True)
        
    class DataInventoryRecord(Base):
        __tablename__ = 'data_inventory'
        
        item_id = Column(String, primary_key=True)
        data_type = Column(String, nullable=False)
        location = Column(String, nullable=False)
        description = Column(Text, nullable=False)
        retention_period = Column(Integer, nullable=False)
        encryption_status = Column(String, nullable=False)
        access_controls = Column(JSON, nullable=False)
        processing_purpose = Column(Text, nullable=False)
        data_subjects = Column(Integer, nullable=False)
        last_accessed = Column(DateTime, nullable=False)
        created_at = Column(DateTime, default=datetime.utcnow)
        
    class AuditTrailRecord(Base):
        __tablename__ = 'compliance_audit_trail'
        
        audit_id = Column(String, primary_key=True)
        timestamp = Column(DateTime, nullable=False)
        user_id = Column(String, nullable=False)
        action = Column(String, nullable=False)
        resource = Column(String, nullable=False)
        data_classification = Column(String, nullable=True)
        source_ip = Column(String, nullable=True)
        user_agent = Column(String, nullable=True)
        success = Column(Boolean, nullable=False)
        details = Column(JSON, nullable=True)

class HIPAAPCIComplianceFramework:
    """
    Comprehensive HIPAA/PCI DSS Compliance Framework for AI/ML systems
    Implements data protection, access controls, and audit requirements
    """
    
    def __init__(
        self,
        database_url: str = "postgresql://localhost/isectech_hipaa_pci_compliance",
        redis_url: str = "redis://localhost:6379/5",
        encryption_key: Optional[bytes] = None
    ):
        """Initialize HIPAA/PCI DSS compliance framework"""
        self.database_url = database_url
        self.redis_url = redis_url
        self.encryption_key = encryption_key or Fernet.generate_key()
        self.cipher_suite = Fernet(self.encryption_key)
        
        # Database setup
        self.engine = create_engine(database_url)
        ComplianceDB.Base.metadata.create_all(self.engine)
        self.SessionLocal = sessionmaker(bind=self.engine)
        
        # Redis for caching
        self.redis_pool = None
        
        # Initialize compliance requirements
        self.requirements = self._initialize_compliance_requirements()
        
        # Data classification patterns
        self.data_patterns = self._initialize_data_patterns()
        
        logger.info("HIPAA/PCI DSS Compliance Framework initialized")

    async def initialize_redis(self) -> None:
        """Initialize Redis connection"""
        if not self.redis_pool:
            self.redis_pool = aioredis.from_url(
                self.redis_url,
                encoding="utf-8",
                decode_responses=True,
                max_connections=10
            )

    def _initialize_compliance_requirements(self) -> Dict[str, ComplianceRequirement]:
        """Initialize HIPAA and PCI DSS requirements"""
        requirements = {}
        
        # HIPAA Requirements
        requirements["HIPAA_164.306"] = ComplianceRequirement(
            requirement_id="HIPAA_164.306",
            framework=ComplianceFramework.HIPAA,
            title="Security Standards - General Rules",
            description="Ensure the confidentiality, integrity, and security of all ePHI",
            control_objective="Protect PHI from unauthorized access, alteration, or destruction",
            implementation_guidance="Implement security measures for AI/ML systems processing PHI",
            testing_procedures=[
                "Review security policies and procedures",
                "Test access controls for PHI data",
                "Verify encryption implementation",
                "Assess audit trail completeness"
            ],
            data_types=[DataClassification.PHI, DataClassification.PII],
            responsible_party="Security Team",
            frequency="Quarterly"
        )
        
        requirements["HIPAA_164.308"] = ComplianceRequirement(
            requirement_id="HIPAA_164.308",
            framework=ComplianceFramework.HIPAA,
            title="Administrative Safeguards",
            description="Implement policies and procedures for accessing and handling PHI",
            control_objective="Establish administrative controls for PHI access and management",
            implementation_guidance="Implement role-based access controls and security awareness training",
            testing_procedures=[
                "Review access authorization procedures",
                "Test workforce training records",
                "Verify incident response procedures",
                "Assess security officer responsibilities"
            ],
            data_types=[DataClassification.PHI],
            responsible_party="Privacy Officer",
            frequency="Annual"
        )
        
        requirements["HIPAA_164.312"] = ComplianceRequirement(
            requirement_id="HIPAA_164.312",
            framework=ComplianceFramework.HIPAA,
            title="Technical Safeguards",
            description="Implement technical controls to protect PHI",
            control_objective="Use technology to control access to PHI and audit access patterns",
            implementation_guidance="Implement encryption, access controls, and audit mechanisms",
            testing_procedures=[
                "Test encryption of PHI at rest and in transit",
                "Verify unique user identification",
                "Test automatic logoff procedures",
                "Assess audit trail generation"
            ],
            data_types=[DataClassification.PHI],
            responsible_party="IT Security Team",
            frequency="Quarterly"
        )
        
        # PCI DSS Requirements
        requirements["PCI_3.4"] = ComplianceRequirement(
            requirement_id="PCI_3.4",
            framework=ComplianceFramework.PCI_DSS,
            title="Protect Cardholder Data",
            description="Render PAN unreadable anywhere it is stored",
            control_objective="Protect stored cardholder data through strong encryption",
            implementation_guidance="Implement AES encryption for cardholder data in AI/ML training datasets",
            testing_procedures=[
                "Verify encryption strength (AES-256)",
                "Test key management procedures",
                "Verify cardholder data identification",
                "Assess data retention policies"
            ],
            data_types=[DataClassification.CHD, DataClassification.PII],
            responsible_party="Data Security Team",
            frequency="Quarterly"
        )
        
        requirements["PCI_8.1"] = ComplianceRequirement(
            requirement_id="PCI_8.1",
            framework=ComplianceFramework.PCI_DSS,
            title="User Identification and Authentication",
            description="Define and implement policies for proper user identification",
            control_objective="Ensure appropriate user identification and authentication",
            implementation_guidance="Implement multi-factor authentication for AI/ML system access",
            testing_procedures=[
                "Verify unique user IDs for each person",
                "Test multi-factor authentication",
                "Review user provisioning procedures",
                "Assess password complexity requirements"
            ],
            data_types=[DataClassification.CHD],
            responsible_party="Identity Management Team",
            frequency="Quarterly"
        )
        
        requirements["PCI_10.1"] = ComplianceRequirement(
            requirement_id="PCI_10.1",
            framework=ComplianceFramework.PCI_DSS,
            title="Audit Trails",
            description="Implement audit trails to link all access to system components",
            control_objective="Track and monitor all access to network resources and cardholder data",
            implementation_guidance="Implement comprehensive logging for AI/ML system access and operations",
            testing_procedures=[
                "Verify audit trail completeness",
                "Test log integrity mechanisms",
                "Review log review procedures",
                "Assess log retention policies"
            ],
            data_types=[DataClassification.CHD],
            responsible_party="Security Operations Team",
            frequency="Monthly"
        )
        
        return requirements

    def _initialize_data_patterns(self) -> Dict[DataClassification, List[str]]:
        """Initialize regex patterns for data classification"""
        return {
            DataClassification.PHI: [
                r'\b\d{3}-\d{2}-\d{4}\b',  # SSN
                r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # Email
                r'\b\d{10,11}\b',  # Phone numbers
                r'\b\d{2}/\d{2}/\d{4}\b',  # Dates (potential DOB)
            ],
            DataClassification.CHD: [
                r'\b4[0-9]{12}(?:[0-9]{3})?\b',  # Visa
                r'\b5[1-5][0-9]{14}\b',  # Mastercard
                r'\b3[47][0-9]{13}\b',  # American Express
                r'\b3[0-9]{4}\s?[0-9]{6}\s?[0-9]{5}\b',  # Diners Club
            ],
            DataClassification.PII: [
                r'\b\d{3}-\d{2}-\d{4}\b',  # SSN
                r'\b[A-Z][a-z]+ [A-Z][a-z]+\b',  # Names
                r'\b\d+ [A-Za-z\s]+ (Street|St|Avenue|Ave|Drive|Dr|Lane|Ln)\b',  # Addresses
            ]
        }

    async def initialize_requirements(self) -> None:
        """Initialize compliance requirements in database"""
        db = self.SessionLocal()
        try:
            for req in self.requirements.values():
                existing = db.query(ComplianceDB.RequirementRecord).filter(
                    ComplianceDB.RequirementRecord.requirement_id == req.requirement_id
                ).first()
                
                if not existing:
                    db_req = ComplianceDB.RequirementRecord(
                        requirement_id=req.requirement_id,
                        framework=req.framework.value,
                        title=req.title,
                        description=req.description,
                        control_objective=req.control_objective,
                        implementation_guidance=req.implementation_guidance,
                        testing_procedures=req.testing_procedures,
                        data_types=[dt.value for dt in req.data_types],
                        responsible_party=req.responsible_party,
                        frequency=req.frequency
                    )
                    db.add(db_req)
            
            db.commit()
            logger.info(f"Initialized {len(self.requirements)} compliance requirements")
            
        except Exception as e:
            db.rollback()
            logger.error(f"Error initializing requirements: {str(e)}")
            raise
        finally:
            db.close()

    async def scan_data_for_classification(
        self,
        data_source: str,
        data_sample: str
    ) -> Dict[DataClassification, List[Dict[str, Any]]]:
        """
        Scan data for sensitive information and classify it
        
        Args:
            data_source: Source identifier (e.g., database table, file path)
            data_sample: Sample of data to scan
            
        Returns:
            Dictionary of detected sensitive data by classification
        """
        detected_data = {classification: [] for classification in DataClassification}
        
        for classification, patterns in self.data_patterns.items():
            for pattern in patterns:
                matches = re.finditer(pattern, data_sample, re.IGNORECASE)
                
                for match in matches:
                    detected_data[classification].append({
                        'pattern': pattern,
                        'match': match.group(),
                        'start_pos': match.start(),
                        'end_pos': match.end(),
                        'source': data_source
                    })
        
        # Log detection results
        total_matches = sum(len(matches) for matches in detected_data.values())
        if total_matches > 0:
            logger.warning(f"Detected {total_matches} potential sensitive data items in {data_source}")
        
        return detected_data

    async def register_data_inventory_item(
        self,
        data_type: DataClassification,
        location: str,
        description: str,
        retention_period: int,
        encryption_status: str,
        access_controls: List[str],
        processing_purpose: str,
        data_subjects: int = 1
    ) -> str:
        """
        Register a data inventory item for compliance tracking
        
        Args:
            data_type: Classification of the data
            location: Where the data is stored
            description: Description of the data
            retention_period: How long to retain the data (days)
            encryption_status: Encryption implementation status
            access_controls: List of access controls in place
            processing_purpose: Purpose for processing the data
            data_subjects: Number of data subjects affected
            
        Returns:
            Inventory item ID
        """
        item_id = str(uuid.uuid4())
        timestamp = datetime.utcnow()
        
        inventory_item = DataInventoryItem(
            item_id=item_id,
            data_type=data_type,
            location=location,
            description=description,
            retention_period=retention_period,
            encryption_status=encryption_status,
            access_controls=access_controls,
            processing_purpose=processing_purpose,
            data_subjects=data_subjects,
            last_accessed=timestamp
        )
        
        # Store in database
        db = self.SessionLocal()
        try:
            db_record = ComplianceDB.DataInventoryRecord(
                item_id=item_id,
                data_type=data_type.value,
                location=location,
                description=description,
                retention_period=retention_period,
                encryption_status=encryption_status,
                access_controls=access_controls,
                processing_purpose=processing_purpose,
                data_subjects=data_subjects,
                last_accessed=timestamp
            )
            
            db.add(db_record)
            db.commit()
            
            logger.info(f"Data inventory item registered: {item_id} ({data_type.value})")
            return item_id
            
        except Exception as e:
            db.rollback()
            logger.error(f"Error registering data inventory item: {str(e)}")
            raise
        finally:
            db.close()

    async def log_data_access(
        self,
        user_id: str,
        action: str,
        resource: str,
        data_classification: Optional[DataClassification] = None,
        source_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
        success: bool = True,
        details: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Log data access for audit trail compliance
        
        Args:
            user_id: User performing the action
            action: Action performed (read, write, delete, etc.)
            resource: Resource accessed
            data_classification: Classification of data accessed
            source_ip: Source IP address
            user_agent: User agent string
            success: Whether the action was successful
            details: Additional details about the action
            
        Returns:
            Audit record ID
        """
        audit_id = str(uuid.uuid4())
        timestamp = datetime.utcnow()
        
        # Store in database
        db = self.SessionLocal()
        try:
            db_record = ComplianceDB.AuditTrailRecord(
                audit_id=audit_id,
                timestamp=timestamp,
                user_id=user_id,
                action=action,
                resource=resource,
                data_classification=data_classification.value if data_classification else None,
                source_ip=source_ip,
                user_agent=user_agent,
                success=success,
                details=details or {}
            )
            
            db.add(db_record)
            db.commit()
            
            # Cache recent audit logs
            await self.initialize_redis()
            cache_key = f"audit_trail:recent:{user_id}"
            recent_logs = await self.redis_pool.get(cache_key)
            
            if recent_logs:
                logs = json.loads(recent_logs)
            else:
                logs = []
            
            logs.append({
                'audit_id': audit_id,
                'timestamp': timestamp.isoformat(),
                'action': action,
                'resource': resource,
                'success': success
            })
            
            # Keep only last 100 entries
            logs = logs[-100:]
            
            await self.redis_pool.setex(
                cache_key,
                3600,  # 1 hour
                json.dumps(logs, default=str)
            )
            
            return audit_id
            
        except Exception as e:
            db.rollback()
            logger.error(f"Error logging data access: {str(e)}")
            raise
        finally:
            db.close()

    async def detect_compliance_violation(
        self,
        requirement_id: str,
        description: str,
        affected_systems: List[str],
        severity: ViolationSeverity = ViolationSeverity.MEDIUM,
        data_exposure_risk: str = "Unknown"
    ) -> str:
        """
        Record a compliance violation
        
        Args:
            requirement_id: Compliance requirement that was violated
            description: Description of the violation
            affected_systems: Systems affected by the violation
            severity: Severity of the violation
            data_exposure_risk: Assessment of data exposure risk
            
        Returns:
            Violation ID
        """
        violation_id = str(uuid.uuid4())
        timestamp = datetime.utcnow()
        
        # Get requirement info
        requirement = self.requirements.get(requirement_id)
        if not requirement:
            raise ValueError(f"Unknown requirement ID: {requirement_id}")
        
        # Generate remediation steps based on requirement
        remediation_steps = self._generate_remediation_steps(requirement, description)
        
        violation = ComplianceViolation(
            violation_id=violation_id,
            requirement_id=requirement_id,
            framework=requirement.framework,
            severity=severity,
            detected_at=timestamp,
            description=description,
            affected_systems=affected_systems,
            data_exposure_risk=data_exposure_risk,
            remediation_steps=remediation_steps,
            status="open",
            resolved_at=None
        )
        
        # Store in database
        db = self.SessionLocal()
        try:
            db_record = ComplianceDB.ViolationRecord(
                violation_id=violation_id,
                requirement_id=requirement_id,
                framework=requirement.framework.value,
                severity=severity.value,
                detected_at=timestamp,
                description=description,
                affected_systems=affected_systems,
                data_exposure_risk=data_exposure_risk,
                remediation_steps=remediation_steps,
                status="open"
            )
            
            db.add(db_record)
            db.commit()
            
            # Generate alert for critical violations
            if severity == ViolationSeverity.CRITICAL:
                await self._send_critical_violation_alert(violation)
            
            logger.warning(f"Compliance violation detected: {violation_id} ({severity.value})")
            return violation_id
            
        except Exception as e:
            db.rollback()
            logger.error(f"Error recording compliance violation: {str(e)}")
            raise
        finally:
            db.close()

    def _generate_remediation_steps(
        self,
        requirement: ComplianceRequirement,
        violation_description: str
    ) -> List[str]:
        """Generate remediation steps based on requirement and violation"""
        base_steps = []
        
        if requirement.framework == ComplianceFramework.HIPAA:
            if "encryption" in violation_description.lower():
                base_steps.extend([
                    "Implement AES-256 encryption for PHI at rest",
                    "Implement TLS 1.2+ for PHI in transit",
                    "Review and update encryption key management procedures"
                ])
            
            if "access" in violation_description.lower():
                base_steps.extend([
                    "Review and update access control policies",
                    "Implement role-based access controls",
                    "Conduct access review and remove unnecessary permissions"
                ])
            
            if "audit" in violation_description.lower():
                base_steps.extend([
                    "Implement comprehensive audit logging",
                    "Review audit trail completeness",
                    "Establish log review procedures"
                ])
        
        elif requirement.framework == ComplianceFramework.PCI_DSS:
            if "cardholder" in violation_description.lower():
                base_steps.extend([
                    "Implement PCI DSS compliant encryption",
                    "Review cardholder data retention policies",
                    "Conduct cardholder data discovery scan"
                ])
            
            if "authentication" in violation_description.lower():
                base_steps.extend([
                    "Implement multi-factor authentication",
                    "Review password policies",
                    "Update user provisioning procedures"
                ])
        
        # Add generic remediation steps
        base_steps.extend([
            f"Review {requirement.title} implementation",
            "Conduct compliance assessment",
            "Update policies and procedures as needed",
            "Provide additional training if required"
        ])
        
        return base_steps

    async def _send_critical_violation_alert(self, violation: ComplianceViolation) -> None:
        """Send alert for critical compliance violations"""
        # In a production system, this would integrate with alerting systems
        # For now, just log the critical violation
        logger.critical(
            f"CRITICAL COMPLIANCE VIOLATION: {violation.violation_id} - "
            f"{violation.framework.value.upper()} - {violation.description}"
        )

    async def assess_ai_ml_compliance(
        self,
        model_name: str,
        training_data_location: str,
        data_types: List[DataClassification]
    ) -> Dict[str, Any]:
        """
        Assess AI/ML system compliance with HIPAA/PCI DSS requirements
        
        Args:
            model_name: Name of the AI/ML model
            training_data_location: Location of training data
            data_types: Types of data used in training
            
        Returns:
            Compliance assessment results
        """
        assessment_results = {
            'model_name': model_name,
            'assessment_timestamp': datetime.utcnow().isoformat(),
            'data_types_assessed': [dt.value for dt in data_types],
            'violations_found': [],
            'recommendations': [],
            'compliance_score': 0
        }
        
        # Check for PHI handling compliance
        if DataClassification.PHI in data_types:
            phi_violations = await self._assess_phi_compliance(model_name, training_data_location)
            assessment_results['violations_found'].extend(phi_violations)
        
        # Check for CHD handling compliance
        if DataClassification.CHD in data_types:
            chd_violations = await self._assess_chd_compliance(model_name, training_data_location)
            assessment_results['violations_found'].extend(chd_violations)
        
        # Calculate compliance score
        total_checks = len(data_types) * 5  # 5 checks per data type
        violations_count = len(assessment_results['violations_found'])
        assessment_results['compliance_score'] = max(0, (total_checks - violations_count) / total_checks * 100)
        
        # Generate recommendations
        assessment_results['recommendations'] = self._generate_compliance_recommendations(
            assessment_results['violations_found'],
            data_types
        )
        
        logger.info(
            f"AI/ML compliance assessment completed for {model_name}: "
            f"{assessment_results['compliance_score']:.1f}% compliant"
        )
        
        return assessment_results

    async def _assess_phi_compliance(self, model_name: str, data_location: str) -> List[Dict[str, Any]]:
        """Assess PHI handling compliance"""
        violations = []
        
        # Check encryption requirement
        # In production, this would check actual encryption status
        encryption_compliant = True  # Placeholder
        if not encryption_compliant:
            violation_id = await self.detect_compliance_violation(
                requirement_id="HIPAA_164.312",
                description=f"PHI data for model {model_name} is not properly encrypted",
                affected_systems=[model_name],
                severity=ViolationSeverity.HIGH,
                data_exposure_risk="High - PHI exposed without encryption"
            )
            violations.append({'violation_id': violation_id, 'type': 'encryption'})
        
        # Check access controls
        access_controls_compliant = True  # Placeholder
        if not access_controls_compliant:
            violation_id = await self.detect_compliance_violation(
                requirement_id="HIPAA_164.308",
                description=f"Access controls for {model_name} PHI data are insufficient",
                affected_systems=[model_name],
                severity=ViolationSeverity.MEDIUM,
                data_exposure_risk="Medium - Potential unauthorized PHI access"
            )
            violations.append({'violation_id': violation_id, 'type': 'access_control'})
        
        return violations

    async def _assess_chd_compliance(self, model_name: str, data_location: str) -> List[Dict[str, Any]]:
        """Assess cardholder data handling compliance"""
        violations = []
        
        # Check PCI DSS encryption requirements
        encryption_compliant = True  # Placeholder
        if not encryption_compliant:
            violation_id = await self.detect_compliance_violation(
                requirement_id="PCI_3.4",
                description=f"Cardholder data for model {model_name} does not meet PCI DSS encryption requirements",
                affected_systems=[model_name],
                severity=ViolationSeverity.CRITICAL,
                data_exposure_risk="Critical - Cardholder data exposure risk"
            )
            violations.append({'violation_id': violation_id, 'type': 'encryption'})
        
        # Check audit trail requirements
        audit_compliant = True  # Placeholder
        if not audit_compliant:
            violation_id = await self.detect_compliance_violation(
                requirement_id="PCI_10.1",
                description=f"Audit trail for {model_name} cardholder data access is incomplete",
                affected_systems=[model_name],
                severity=ViolationSeverity.HIGH,
                data_exposure_risk="High - Inability to track cardholder data access"
            )
            violations.append({'violation_id': violation_id, 'type': 'audit_trail'})
        
        return violations

    def _generate_compliance_recommendations(
        self,
        violations: List[Dict[str, Any]],
        data_types: List[DataClassification]
    ) -> List[str]:
        """Generate compliance recommendations"""
        recommendations = []
        
        if violations:
            recommendations.append("Address identified compliance violations immediately")
            recommendations.append("Implement comprehensive audit logging for all data access")
        
        if DataClassification.PHI in data_types:
            recommendations.extend([
                "Ensure HIPAA Business Associate Agreements are in place",
                "Implement minimum necessary standard for PHI access",
                "Conduct regular HIPAA risk assessments"
            ])
        
        if DataClassification.CHD in data_types:
            recommendations.extend([
                "Validate PCI DSS compliance scope regularly",
                "Implement strong access control measures for cardholder data",
                "Conduct quarterly vulnerability scans"
            ])
        
        recommendations.extend([
            "Implement data loss prevention (DLP) controls",
            "Conduct regular employee training on data protection",
            "Establish incident response procedures for data breaches"
        ])
        
        return recommendations

    async def generate_compliance_report(
        self,
        framework: ComplianceFramework,
        start_date: datetime,
        end_date: datetime
    ) -> Dict[str, Any]:
        """
        Generate comprehensive compliance report
        
        Args:
            framework: HIPAA or PCI DSS
            start_date: Report period start
            end_date: Report period end
            
        Returns:
            Compliance report
        """
        db = self.SessionLocal()
        try:
            # Get violations for the period
            violations = db.query(ComplianceDB.ViolationRecord).filter(
                ComplianceDB.ViolationRecord.framework == framework.value,
                ComplianceDB.ViolationRecord.detected_at.between(start_date, end_date)
            ).all()
            
            # Get audit trail activity
            audit_records = db.query(ComplianceDB.AuditTrailRecord).filter(
                ComplianceDB.AuditTrailRecord.timestamp.between(start_date, end_date)
            ).count()
            
            # Get data inventory for this framework
            relevant_data_types = []
            if framework == ComplianceFramework.HIPAA:
                relevant_data_types = [DataClassification.PHI.value, DataClassification.PII.value]
            elif framework == ComplianceFramework.PCI_DSS:
                relevant_data_types = [DataClassification.CHD.value, DataClassification.PII.value]
            
            data_inventory = db.query(ComplianceDB.DataInventoryRecord).filter(
                ComplianceDB.DataInventoryRecord.data_type.in_(relevant_data_types)
            ).all()
            
            # Calculate compliance metrics
            total_requirements = len([r for r in self.requirements.values() if r.framework == framework])
            violation_requirements = len(set(v.requirement_id for v in violations))
            compliant_requirements = total_requirements - violation_requirements
            compliance_percentage = (compliant_requirements / total_requirements * 100) if total_requirements > 0 else 0
            
            # Violation analysis
            violation_severity_counts = {}
            for violation in violations:
                violation_severity_counts[violation.severity] = \
                    violation_severity_counts.get(violation.severity, 0) + 1
            
            # Generate report
            report = {
                'framework': framework.value.upper(),
                'report_period': {
                    'start_date': start_date.isoformat(),
                    'end_date': end_date.isoformat()
                },
                'executive_summary': {
                    'compliance_percentage': compliance_percentage,
                    'total_requirements': total_requirements,
                    'compliant_requirements': compliant_requirements,
                    'violation_count': len(violations),
                    'critical_violations': violation_severity_counts.get('critical', 0),
                    'audit_trail_records': audit_records,
                    'data_inventory_items': len(data_inventory)
                },
                'violations_analysis': {
                    'by_severity': violation_severity_counts,
                    'by_requirement': {v.requirement_id: len([x for x in violations if x.requirement_id == v.requirement_id]) 
                                     for v in violations},
                    'resolution_status': {
                        'open': len([v for v in violations if v.status == 'open']),
                        'in_progress': len([v for v in violations if v.status == 'in_progress']),
                        'resolved': len([v for v in violations if v.status == 'resolved'])
                    }
                },
                'data_inventory_summary': {
                    'total_items': len(data_inventory),
                    'by_classification': {
                        dt: len([item for item in data_inventory if item.data_type == dt])
                        for dt in relevant_data_types
                    },
                    'encryption_status': {
                        'encrypted': len([item for item in data_inventory if 'encrypted' in item.encryption_status.lower()]),
                        'not_encrypted': len([item for item in data_inventory if 'not' in item.encryption_status.lower()])
                    }
                },
                'recommendations': self._generate_framework_recommendations(framework, violations, data_inventory),
                'generated_at': datetime.utcnow().isoformat()
            }
            
            logger.info(f"{framework.value.upper()} compliance report generated: {compliance_percentage:.1f}% compliant")
            return report
            
        except Exception as e:
            logger.error(f"Error generating compliance report: {str(e)}")
            raise
        finally:
            db.close()

    def _generate_framework_recommendations(
        self,
        framework: ComplianceFramework,
        violations: List[ComplianceDB.ViolationRecord],
        data_inventory: List[ComplianceDB.DataInventoryRecord]
    ) -> List[str]:
        """Generate framework-specific recommendations"""
        recommendations = []
        
        if framework == ComplianceFramework.HIPAA:
            recommendations.extend([
                "Ensure all PHI is encrypted with AES-256 or equivalent",
                "Implement comprehensive access controls with role-based permissions",
                "Conduct annual HIPAA risk assessments",
                "Maintain complete audit trails for all PHI access"
            ])
            
            if violations:
                recommendations.insert(0, "Address all identified HIPAA violations immediately to maintain compliance")
        
        elif framework == ComplianceFramework.PCI_DSS:
            recommendations.extend([
                "Ensure cardholder data is protected with PCI DSS approved encryption",
                "Implement strong access control measures",
                "Conduct quarterly vulnerability scans",
                "Maintain secure network architecture"
            ])
            
            if violations:
                recommendations.insert(0, "Remediate PCI DSS violations to maintain merchant status")
        
        # Data inventory recommendations
        unencrypted_items = [item for item in data_inventory if 'not' in item.encryption_status.lower()]
        if unencrypted_items:
            recommendations.append(f"Encrypt {len(unencrypted_items)} unencrypted sensitive data items")
        
        return recommendations

# Convenience functions for AI/ML integration
async def setup_ai_ml_hipaa_compliance(
    framework: HIPAAPCIComplianceFramework,
    model_name: str,
    training_data_location: str
) -> Dict[str, Any]:
    """Setup HIPAA compliance for AI/ML model"""
    
    # Initialize requirements
    await framework.initialize_requirements()
    
    # Register training data in inventory
    inventory_id = await framework.register_data_inventory_item(
        data_type=DataClassification.PHI,
        location=training_data_location,
        description=f"Training data for {model_name} AI/ML model",
        retention_period=2555,  # 7 years
        encryption_status="AES-256 encrypted",
        access_controls=["Role-based access", "Multi-factor authentication"],
        processing_purpose="AI/ML model training for threat detection",
        data_subjects=1000  # Estimated
    )
    
    # Conduct compliance assessment
    assessment = await framework.assess_ai_ml_compliance(
        model_name=model_name,
        training_data_location=training_data_location,
        data_types=[DataClassification.PHI, DataClassification.PII]
    )
    
    return {
        'inventory_id': inventory_id,
        'assessment': assessment,
        'setup_completed': True
    }

async def setup_ai_ml_pci_compliance(
    framework: HIPAAPCIComplianceFramework,
    model_name: str,
    training_data_location: str
) -> Dict[str, Any]:
    """Setup PCI DSS compliance for AI/ML model"""
    
    # Initialize requirements
    await framework.initialize_requirements()
    
    # Register cardholder data in inventory
    inventory_id = await framework.register_data_inventory_item(
        data_type=DataClassification.CHD,
        location=training_data_location,
        description=f"Cardholder data for {model_name} AI/ML model",
        retention_period=365,  # 1 year
        encryption_status="PCI DSS compliant encryption",
        access_controls=["Strong access control", "Multi-factor authentication", "Network segmentation"],
        processing_purpose="AI/ML model training for fraud detection",
        data_subjects=5000  # Estimated
    )
    
    # Conduct compliance assessment
    assessment = await framework.assess_ai_ml_compliance(
        model_name=model_name,
        training_data_location=training_data_location,
        data_types=[DataClassification.CHD, DataClassification.PII]
    )
    
    return {
        'inventory_id': inventory_id,
        'assessment': assessment,
        'setup_completed': True
    }

if __name__ == "__main__":
    # Example usage and testing
    async def test_hipaa_pci_compliance():
        framework = HIPAAPCIComplianceFramework()
        
        # Setup HIPAA compliance
        hipaa_setup = await setup_ai_ml_hipaa_compliance(
            framework, "threat-detection-model", "/data/training/phi_data"
        )
        print(f"HIPAA setup completed: {hipaa_setup['assessment']['compliance_score']:.1f}% compliant")
        
        # Setup PCI DSS compliance
        pci_setup = await setup_ai_ml_pci_compliance(
            framework, "fraud-detection-model", "/data/training/chd_data"
        )
        print(f"PCI DSS setup completed: {pci_setup['assessment']['compliance_score']:.1f}% compliant")
        
        # Log some data access
        audit_id = await framework.log_data_access(
            user_id="data_scientist_1",
            action="model_training",
            resource="threat-detection-model",
            data_classification=DataClassification.PHI,
            source_ip="192.168.1.100",
            success=True
        )
        print(f"Data access logged: {audit_id}")
        
        # Generate compliance reports
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=30)
        
        hipaa_report = await framework.generate_compliance_report(
            ComplianceFramework.HIPAA, start_date, end_date
        )
        print(f"HIPAA report: {hipaa_report['executive_summary']['compliance_percentage']:.1f}% compliant")
        
        pci_report = await framework.generate_compliance_report(
            ComplianceFramework.PCI_DSS, start_date, end_date
        )
        print(f"PCI DSS report: {pci_report['executive_summary']['compliance_percentage']:.1f}% compliant")
    
    # Run test
    asyncio.run(test_hipaa_pci_compliance())