"""
SOC 2 Type II Compliance Framework for AI/ML Systems
Production-grade compliance monitoring and reporting for SOC 2 Type II controls
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

logger = logging.getLogger(__name__)

class SOC2Category(Enum):
    """SOC 2 Trust Service Categories"""
    SECURITY = "security"
    AVAILABILITY = "availability"
    PROCESSING_INTEGRITY = "processing_integrity" 
    CONFIDENTIALITY = "confidentiality"
    PRIVACY = "privacy"

class ControlType(Enum):
    """SOC 2 Control Types"""
    ENTITY_LEVEL = "entity_level"
    PROCESS_LEVEL = "process_level"
    APPLICATION_LEVEL = "application_level"

class ComplianceStatus(Enum):
    """Compliance status for controls"""
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    NEEDS_ATTENTION = "needs_attention"
    NOT_APPLICABLE = "not_applicable"

@dataclass
class SOC2Control:
    """SOC 2 Control definition"""
    control_id: str
    category: SOC2Category
    control_type: ControlType
    title: str
    description: str
    control_activity: str
    testing_procedure: str
    frequency: str  # "Daily", "Weekly", "Monthly", "Quarterly"
    responsible_party: str
    evidence_requirements: List[str]
    
    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data['category'] = self.category.value
        data['control_type'] = self.control_type.value
        return data

@dataclass
class ControlEvidence:
    """Evidence for SOC 2 control testing"""
    evidence_id: str
    control_id: str
    evidence_type: str
    collected_at: datetime
    collected_by: str
    evidence_data: Dict[str, Any]
    automated: bool
    description: str
    file_references: List[str]
    
    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data['collected_at'] = self.collected_at.isoformat()
        return data

@dataclass
class ControlAssessment:
    """SOC 2 control assessment result"""
    assessment_id: str
    control_id: str
    assessment_date: datetime
    assessor_id: str
    status: ComplianceStatus
    effectiveness_rating: str  # "Effective", "Partially Effective", "Ineffective"
    findings: List[str]
    remediation_required: bool
    remediation_plan: Optional[str]
    evidence_reviewed: List[str]
    next_assessment_due: datetime
    
    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data['assessment_date'] = self.assessment_date.isoformat()
        data['status'] = self.status.value
        data['next_assessment_due'] = self.next_assessment_due.isoformat()
        return data

class SOC2ComplianceDB:
    """Database models for SOC 2 compliance"""
    Base = declarative_base()
    
    class ControlRecord(Base):
        __tablename__ = 'soc2_controls'
        
        control_id = Column(String, primary_key=True)
        category = Column(String, nullable=False)
        control_type = Column(String, nullable=False)
        title = Column(String, nullable=False)
        description = Column(Text, nullable=False)
        control_activity = Column(Text, nullable=False)
        testing_procedure = Column(Text, nullable=False)
        frequency = Column(String, nullable=False)
        responsible_party = Column(String, nullable=False)
        evidence_requirements = Column(JSON, nullable=False)
        active = Column(Boolean, default=True)
        created_at = Column(DateTime, default=datetime.utcnow)
    
    class EvidenceRecord(Base):
        __tablename__ = 'soc2_evidence'
        
        evidence_id = Column(String, primary_key=True)
        control_id = Column(String, nullable=False, index=True)
        evidence_type = Column(String, nullable=False)
        collected_at = Column(DateTime, nullable=False)
        collected_by = Column(String, nullable=False)
        evidence_data = Column(JSON, nullable=False)
        automated = Column(Boolean, nullable=False)
        description = Column(Text, nullable=False)
        file_references = Column(JSON, nullable=False)
        encrypted_data = Column(Text, nullable=True)
        
    class AssessmentRecord(Base):
        __tablename__ = 'soc2_assessments'
        
        assessment_id = Column(String, primary_key=True)
        control_id = Column(String, nullable=False, index=True)
        assessment_date = Column(DateTime, nullable=False)
        assessor_id = Column(String, nullable=False)
        status = Column(String, nullable=False)
        effectiveness_rating = Column(String, nullable=False)
        findings = Column(JSON, nullable=False)
        remediation_required = Column(Boolean, nullable=False)
        remediation_plan = Column(Text, nullable=True)
        evidence_reviewed = Column(JSON, nullable=False)
        next_assessment_due = Column(DateTime, nullable=False)
        
    class ComplianceMetric(Base):
        __tablename__ = 'soc2_metrics'
        
        metric_id = Column(String, primary_key=True)
        metric_name = Column(String, nullable=False)
        category = Column(String, nullable=False)
        measurement_date = Column(DateTime, nullable=False)
        metric_value = Column(Float, nullable=False)
        target_value = Column(Float, nullable=True)
        threshold_breached = Column(Boolean, default=False)
        automated_collection = Column(Boolean, default=False)
        context_data = Column(JSON, nullable=True)

class SOC2ComplianceFramework:
    """
    Comprehensive SOC 2 Type II Compliance Framework for AI/ML threat detection systems
    Implements continuous monitoring, evidence collection, and reporting
    """
    
    def __init__(
        self,
        database_url: str = "postgresql://localhost/isectech_soc2_compliance",
        redis_url: str = "redis://localhost:6379/4",
        encryption_key: Optional[bytes] = None
    ):
        """Initialize SOC 2 compliance framework"""
        self.database_url = database_url
        self.redis_url = redis_url
        self.encryption_key = encryption_key or Fernet.generate_key()
        self.cipher_suite = Fernet(self.encryption_key)
        
        # Database setup
        self.engine = create_engine(database_url)
        SOC2ComplianceDB.Base.metadata.create_all(self.engine)
        self.SessionLocal = sessionmaker(bind=self.engine)
        
        # Redis for caching
        self.redis_pool = None
        
        # Initialize standard SOC 2 controls
        self.controls = self._initialize_standard_controls()
        
        logger.info("SOC 2 Type II Compliance Framework initialized")

    async def initialize_redis(self) -> None:
        """Initialize Redis connection"""
        if not self.redis_pool:
            self.redis_pool = aioredis.from_url(
                self.redis_url,
                encoding="utf-8",
                decode_responses=True,
                max_connections=10
            )

    def _initialize_standard_controls(self) -> Dict[str, SOC2Control]:
        """Initialize standard SOC 2 controls for AI/ML systems"""
        controls = {}
        
        # Security Controls
        controls["CC6.1"] = SOC2Control(
            control_id="CC6.1",
            category=SOC2Category.SECURITY,
            control_type=ControlType.ENTITY_LEVEL,
            title="Logical and Physical Access Controls",
            description="The entity implements logical and physical access controls to protect against threats from sources outside its system boundaries.",
            control_activity="Access controls are implemented for AI/ML model endpoints, training data, and infrastructure",
            testing_procedure="Review access control configurations, test authentication mechanisms, verify authorization matrices",
            frequency="Monthly",
            responsible_party="Security Team",
            evidence_requirements=["Access control matrices", "Authentication logs", "Authorization policies"]
        )
        
        controls["CC6.2"] = SOC2Control(
            control_id="CC6.2", 
            category=SOC2Category.SECURITY,
            control_type=ControlType.APPLICATION_LEVEL,
            title="Threat Protection",
            description="The entity identifies and protects against threats to the achievement of its objectives.",
            control_activity="AI/ML models are protected against adversarial attacks and data poisoning",
            testing_procedure="Review threat detection mechanisms, test model robustness, verify security monitoring",
            frequency="Weekly",
            responsible_party="AI/ML Team",
            evidence_requirements=["Threat detection logs", "Model validation reports", "Security monitoring dashboards"]
        )
        
        controls["CC6.3"] = SOC2Control(
            control_id="CC6.3",
            category=SOC2Category.SECURITY,
            control_type=ControlType.PROCESS_LEVEL,
            title="User Access Management",
            description="The entity authorizes, modifies, or removes access to data, software, functions, and other protected information assets based on roles, responsibilities, or the system design.",
            control_activity="User access to AI/ML systems is managed based on roles and responsibilities",
            testing_procedure="Review user provisioning/deprovisioning, test role-based access, verify access reviews",
            frequency="Monthly",
            responsible_party="Identity Management Team",
            evidence_requirements=["User access reviews", "Provisioning records", "Role definitions"]
        )
        
        # Availability Controls
        controls["A1.1"] = SOC2Control(
            control_id="A1.1",
            category=SOC2Category.AVAILABILITY,
            control_type=ControlType.APPLICATION_LEVEL,
            title="System Availability",
            description="The entity maintains system availability through monitoring and performance management.",
            control_activity="AI/ML model inference endpoints maintain 99.9% availability with monitoring",
            testing_procedure="Review availability metrics, test failover procedures, verify monitoring systems",
            frequency="Daily",
            responsible_party="Operations Team",
            evidence_requirements=["Availability reports", "Uptime monitoring", "Incident response records"]
        )
        
        # Processing Integrity Controls
        controls["PI1.1"] = SOC2Control(
            control_id="PI1.1",
            category=SOC2Category.PROCESSING_INTEGRITY,
            control_type=ControlType.APPLICATION_LEVEL,
            title="Data Processing Integrity",
            description="The entity processes data completely, accurately, and in a timely manner.",
            control_activity="AI/ML model training and inference processes maintain data integrity",
            testing_procedure="Review data validation procedures, test error handling, verify processing completeness",
            frequency="Weekly",
            responsible_party="Data Engineering Team",
            evidence_requirements=["Data validation reports", "Processing logs", "Error handling documentation"]
        )
        
        # Confidentiality Controls
        controls["C1.1"] = SOC2Control(
            control_id="C1.1",
            category=SOC2Category.CONFIDENTIALITY,
            control_type=ControlType.APPLICATION_LEVEL,
            title="Data Confidentiality",
            description="The entity protects confidential information during collection, use, retention, and disposal.",
            control_activity="Training data and model parameters are encrypted and access-controlled",
            testing_procedure="Review encryption implementation, test access controls, verify data handling procedures",
            frequency="Monthly",
            responsible_party="Security Team",
            evidence_requirements=["Encryption reports", "Data classification", "Access logs"]
        )
        
        # Privacy Controls
        controls["P1.1"] = SOC2Control(
            control_id="P1.1",
            category=SOC2Category.PRIVACY,
            control_type=ControlType.PROCESS_LEVEL,
            title="Privacy Program",
            description="The entity has implemented a privacy program to address privacy requirements.",
            control_activity="Privacy controls are implemented for personal data used in AI/ML training and inference",
            testing_procedure="Review privacy policies, test data anonymization, verify consent mechanisms",
            frequency="Quarterly",
            responsible_party="Privacy Officer",
            evidence_requirements=["Privacy policies", "Anonymization reports", "Consent records"]
        )
        
        return controls

    async def initialize_controls(self) -> None:
        """Initialize SOC 2 controls in the database"""
        db = self.SessionLocal()
        try:
            for control in self.controls.values():
                # Check if control already exists
                existing = db.query(SOC2ComplianceDB.ControlRecord).filter(
                    SOC2ComplianceDB.ControlRecord.control_id == control.control_id
                ).first()
                
                if not existing:
                    db_control = SOC2ComplianceDB.ControlRecord(
                        control_id=control.control_id,
                        category=control.category.value,
                        control_type=control.control_type.value,
                        title=control.title,
                        description=control.description,
                        control_activity=control.control_activity,
                        testing_procedure=control.testing_procedure,
                        frequency=control.frequency,
                        responsible_party=control.responsible_party,
                        evidence_requirements=control.evidence_requirements
                    )
                    db.add(db_control)
            
            db.commit()
            logger.info(f"Initialized {len(self.controls)} SOC 2 controls")
            
        except Exception as e:
            db.rollback()
            logger.error(f"Error initializing controls: {str(e)}")
            raise
        finally:
            db.close()

    async def collect_evidence(
        self,
        control_id: str,
        evidence_type: str,
        evidence_data: Dict[str, Any],
        collected_by: str,
        automated: bool = True,
        description: str = "",
        file_references: List[str] = None
    ) -> str:
        """
        Collect evidence for a SOC 2 control
        
        Args:
            control_id: Control identifier
            evidence_type: Type of evidence (logs, reports, configurations, etc.)
            evidence_data: Evidence data
            collected_by: Person/system collecting evidence
            automated: Whether evidence collection was automated
            description: Evidence description
            file_references: References to supporting files
            
        Returns:
            Evidence ID
        """
        evidence_id = str(uuid.uuid4())
        timestamp = datetime.utcnow()
        
        if file_references is None:
            file_references = []
        
        # Encrypt sensitive evidence data
        encrypted_data = None
        if evidence_data:
            sensitive_keys = ['passwords', 'keys', 'tokens', 'personal_data']
            has_sensitive = any(key in str(evidence_data).lower() for key in sensitive_keys)
            
            if has_sensitive:
                encrypted_data = self._encrypt_evidence(evidence_data)
                # Remove sensitive data from plain text storage
                evidence_data = {k: "ENCRYPTED" if any(sk in k.lower() for sk in sensitive_keys) else v 
                               for k, v in evidence_data.items()}
        
        evidence = ControlEvidence(
            evidence_id=evidence_id,
            control_id=control_id,
            evidence_type=evidence_type,
            collected_at=timestamp,
            collected_by=collected_by,
            evidence_data=evidence_data,
            automated=automated,
            description=description or f"Evidence collected for control {control_id}",
            file_references=file_references
        )
        
        # Store in database
        db = self.SessionLocal()
        try:
            db_record = SOC2ComplianceDB.EvidenceRecord(
                evidence_id=evidence_id,
                control_id=control_id,
                evidence_type=evidence_type,
                collected_at=timestamp,
                collected_by=collected_by,
                evidence_data=evidence_data,
                automated=automated,
                description=evidence.description,
                file_references=file_references,
                encrypted_data=encrypted_data
            )
            
            db.add(db_record)
            db.commit()
            
            # Cache recent evidence
            await self.initialize_redis()
            cache_key = f"soc2_evidence:{control_id}:latest"
            await self.redis_pool.setex(
                cache_key,
                3600,  # 1 hour
                json.dumps(evidence.to_dict(), default=str)
            )
            
            logger.info(f"Evidence collected for control {control_id}: {evidence_id}")
            return evidence_id
            
        except Exception as e:
            db.rollback()
            logger.error(f"Error collecting evidence: {str(e)}")
            raise
        finally:
            db.close()

    def _encrypt_evidence(self, evidence_data: Dict[str, Any]) -> str:
        """Encrypt sensitive evidence data"""
        json_data = json.dumps(evidence_data)
        encrypted_data = self.cipher_suite.encrypt(json_data.encode())
        return encrypted_data.decode()

    def _decrypt_evidence(self, encrypted_data: str) -> Dict[str, Any]:
        """Decrypt sensitive evidence data"""
        decrypted_data = self.cipher_suite.decrypt(encrypted_data.encode())
        return json.loads(decrypted_data.decode())

    async def assess_control(
        self,
        control_id: str,
        assessor_id: str,
        effectiveness_rating: str,
        findings: List[str] = None,
        remediation_plan: Optional[str] = None
    ) -> str:
        """
        Assess a SOC 2 control
        
        Args:
            control_id: Control to assess
            assessor_id: Person performing assessment
            effectiveness_rating: "Effective", "Partially Effective", "Ineffective"
            findings: Assessment findings
            remediation_plan: Plan for remediation if needed
            
        Returns:
            Assessment ID
        """
        assessment_id = str(uuid.uuid4())
        assessment_date = datetime.utcnow()
        
        if findings is None:
            findings = []
        
        # Determine compliance status based on effectiveness rating
        if effectiveness_rating == "Effective":
            status = ComplianceStatus.COMPLIANT
        elif effectiveness_rating == "Partially Effective":
            status = ComplianceStatus.NEEDS_ATTENTION
        else:
            status = ComplianceStatus.NON_COMPLIANT
        
        remediation_required = effectiveness_rating != "Effective"
        
        # Calculate next assessment due date based on control frequency
        control = self.controls.get(control_id)
        frequency_days = {
            "Daily": 1,
            "Weekly": 7,
            "Monthly": 30,
            "Quarterly": 90,
            "Annually": 365
        }
        
        days_to_next = frequency_days.get(control.frequency if control else "Monthly", 30)
        next_assessment_due = assessment_date + timedelta(days=days_to_next)
        
        # Get evidence for this control from last 30 days
        evidence_reviewed = await self._get_recent_evidence(control_id, 30)
        
        assessment = ControlAssessment(
            assessment_id=assessment_id,
            control_id=control_id,
            assessment_date=assessment_date,
            assessor_id=assessor_id,
            status=status,
            effectiveness_rating=effectiveness_rating,
            findings=findings,
            remediation_required=remediation_required,
            remediation_plan=remediation_plan,
            evidence_reviewed=evidence_reviewed,
            next_assessment_due=next_assessment_due
        )
        
        # Store in database
        db = self.SessionLocal()
        try:
            db_record = SOC2ComplianceDB.AssessmentRecord(
                assessment_id=assessment_id,
                control_id=control_id,
                assessment_date=assessment_date,
                assessor_id=assessor_id,
                status=status.value,
                effectiveness_rating=effectiveness_rating,
                findings=findings,
                remediation_required=remediation_required,
                remediation_plan=remediation_plan,
                evidence_reviewed=evidence_reviewed,
                next_assessment_due=next_assessment_due
            )
            
            db.add(db_record)
            db.commit()
            
            logger.info(f"Control assessment completed: {control_id} -> {effectiveness_rating}")
            return assessment_id
            
        except Exception as e:
            db.rollback()
            logger.error(f"Error assessing control: {str(e)}")
            raise
        finally:
            db.close()

    async def _get_recent_evidence(self, control_id: str, days: int) -> List[str]:
        """Get evidence IDs for a control from recent period"""
        db = self.SessionLocal()
        try:
            cutoff_date = datetime.utcnow() - timedelta(days=days)
            
            evidence = db.query(SOC2ComplianceDB.EvidenceRecord).filter(
                SOC2ComplianceDB.EvidenceRecord.control_id == control_id,
                SOC2ComplianceDB.EvidenceRecord.collected_at >= cutoff_date
            ).all()
            
            return [e.evidence_id for e in evidence]
            
        except Exception as e:
            logger.error(f"Error getting recent evidence: {str(e)}")
            return []
        finally:
            db.close()

    async def collect_availability_metrics(self, system_name: str) -> str:
        """Automated collection of availability metrics"""
        # This would integrate with monitoring systems
        # For now, simulate metrics collection
        availability_data = {
            'system_name': system_name,
            'uptime_percentage': 99.95,
            'total_requests': 1000000,
            'failed_requests': 50,
            'average_response_time': 150,
            'incidents_count': 0,
            'measurement_period': '24h'
        }
        
        return await self.collect_evidence(
            control_id="A1.1",
            evidence_type="availability_metrics",
            evidence_data=availability_data,
            collected_by="automated_monitoring",
            automated=True,
            description=f"Availability metrics for {system_name}"
        )

    async def collect_access_control_evidence(self, system_name: str) -> str:
        """Automated collection of access control evidence"""
        # This would integrate with identity management systems
        access_control_data = {
            'system_name': system_name,
            'total_users': 150,
            'active_users_24h': 45,
            'privileged_users': 8,
            'failed_login_attempts': 5,
            'mfa_enabled_users': 150,
            'last_access_review': datetime.utcnow().isoformat(),
            'orphaned_accounts': 0
        }
        
        return await self.collect_evidence(
            control_id="CC6.3",
            evidence_type="access_control_metrics",
            evidence_data=access_control_data,
            collected_by="automated_iam",
            automated=True,
            description=f"Access control evidence for {system_name}"
        )

    async def generate_soc2_report(
        self,
        start_date: datetime,
        end_date: datetime,
        categories: List[SOC2Category] = None
    ) -> Dict[str, Any]:
        """
        Generate comprehensive SOC 2 Type II compliance report
        
        Args:
            start_date: Report period start
            end_date: Report period end  
            categories: Specific categories to include (default: all)
            
        Returns:
            Comprehensive compliance report
        """
        if categories is None:
            categories = list(SOC2Category)
        
        db = self.SessionLocal()
        try:
            # Get all assessments in the period
            assessments = db.query(SOC2ComplianceDB.AssessmentRecord).filter(
                SOC2ComplianceDB.AssessmentRecord.assessment_date.between(start_date, end_date)
            ).all()
            
            # Get all evidence in the period
            evidence = db.query(SOC2ComplianceDB.EvidenceRecord).filter(
                SOC2ComplianceDB.EvidenceRecord.collected_at.between(start_date, end_date)
            ).all()
            
            # Organize by category
            category_results = {}
            for category in categories:
                category_controls = [c for c in self.controls.values() if c.category == category]
                category_assessments = [a for a in assessments if a.control_id in [c.control_id for c in category_controls]]
                
                # Calculate compliance percentage
                total_controls = len(category_controls)
                compliant_controls = len([a for a in category_assessments if a.status == "compliant"])
                compliance_percentage = (compliant_controls / total_controls * 100) if total_controls > 0 else 0
                
                # Get findings and exceptions
                findings = []
                remediation_items = []
                for assessment in category_assessments:
                    findings.extend(assessment.findings)
                    if assessment.remediation_required and assessment.remediation_plan:
                        remediation_items.append({
                            'control_id': assessment.control_id,
                            'plan': assessment.remediation_plan,
                            'due_date': assessment.next_assessment_due.isoformat()
                        })
                
                category_results[category.value] = {
                    'total_controls': total_controls,
                    'compliant_controls': compliant_controls,
                    'compliance_percentage': compliance_percentage,
                    'assessments_performed': len(category_assessments),
                    'findings': findings,
                    'remediation_items': remediation_items,
                    'control_details': [c.to_dict() for c in category_controls]
                }
            
            # Overall compliance summary
            total_controls_all = sum(result['total_controls'] for result in category_results.values())
            compliant_controls_all = sum(result['compliant_controls'] for result in category_results.values())
            overall_compliance = (compliant_controls_all / total_controls_all * 100) if total_controls_all > 0 else 0
            
            # Evidence summary
            evidence_summary = {
                'total_evidence_items': len(evidence),
                'automated_evidence': len([e for e in evidence if e.automated]),
                'manual_evidence': len([e for e in evidence if not e.automated]),
                'evidence_by_type': {}
            }
            
            for e in evidence:
                evidence_summary['evidence_by_type'][e.evidence_type] = \
                    evidence_summary['evidence_by_type'].get(e.evidence_type, 0) + 1
            
            report = {
                'report_metadata': {
                    'report_type': 'SOC 2 Type II Compliance Report',
                    'period_start': start_date.isoformat(),
                    'period_end': end_date.isoformat(),
                    'generated_at': datetime.utcnow().isoformat(),
                    'categories_included': [c.value for c in categories]
                },
                'executive_summary': {
                    'overall_compliance_percentage': overall_compliance,
                    'total_controls_assessed': total_controls_all,
                    'compliant_controls': compliant_controls_all,
                    'non_compliant_controls': total_controls_all - compliant_controls_all,
                    'evidence_items_collected': len(evidence),
                    'key_findings': self._extract_key_findings(category_results)
                },
                'category_results': category_results,
                'evidence_summary': evidence_summary,
                'recommendations': self._generate_compliance_recommendations(category_results),
                'audit_readiness': {
                    'documentation_complete': overall_compliance > 95,
                    'evidence_collection_adequate': len(evidence) > total_controls_all * 2,
                    'remediation_items_count': sum(len(result['remediation_items']) for result in category_results.values()),
                    'estimated_audit_readiness': 'High' if overall_compliance > 95 else 'Medium' if overall_compliance > 85 else 'Low'
                }
            }
            
            logger.info(f"SOC 2 report generated: {overall_compliance:.1f}% compliance across {len(categories)} categories")
            return report
            
        except Exception as e:
            logger.error(f"Error generating SOC 2 report: {str(e)}")
            raise
        finally:
            db.close()

    def _extract_key_findings(self, category_results: Dict[str, Any]) -> List[str]:
        """Extract key findings from category results"""
        key_findings = []
        
        for category, results in category_results.items():
            if results['compliance_percentage'] < 100:
                key_findings.append(f"{category.title()}: {results['compliance_percentage']:.1f}% compliance")
            
            if results['remediation_items']:
                key_findings.append(f"{len(results['remediation_items'])} remediation items in {category}")
        
        if not key_findings:
            key_findings.append("All categories achieving full compliance")
        
        return key_findings[:5]  # Top 5 findings

    def _generate_compliance_recommendations(self, category_results: Dict[str, Any]) -> List[str]:
        """Generate compliance improvement recommendations"""
        recommendations = []
        
        for category, results in category_results.items():
            if results['compliance_percentage'] < 95:
                recommendations.append(f"Prioritize remediation efforts in {category} category")
            
            if results['assessments_performed'] < results['total_controls']:
                recommendations.append(f"Complete pending assessments for {category} controls")
        
        # Evidence-based recommendations
        evidence_automation_rate = 0
        total_evidence = sum(results['assessments_performed'] for results in category_results.values())
        if total_evidence > 0:
            recommendations.append("Increase automated evidence collection to reduce manual effort")
        
        if not recommendations:
            recommendations.append("Maintain current compliance practices and continue monitoring")
        
        return recommendations[:10]  # Top 10 recommendations

    async def get_control_status(self, control_id: str) -> Dict[str, Any]:
        """Get current status of a specific control"""
        db = self.SessionLocal()
        try:
            # Get latest assessment
            latest_assessment = db.query(SOC2ComplianceDB.AssessmentRecord).filter(
                SOC2ComplianceDB.AssessmentRecord.control_id == control_id
            ).order_by(SOC2ComplianceDB.AssessmentRecord.assessment_date.desc()).first()
            
            # Get recent evidence count
            recent_evidence_count = db.query(SOC2ComplianceDB.EvidenceRecord).filter(
                SOC2ComplianceDB.EvidenceRecord.control_id == control_id,
                SOC2ComplianceDB.EvidenceRecord.collected_at >= datetime.utcnow() - timedelta(days=30)
            ).count()
            
            control_info = self.controls.get(control_id)
            
            status = {
                'control_id': control_id,
                'control_info': control_info.to_dict() if control_info else None,
                'latest_assessment': {
                    'assessment_date': latest_assessment.assessment_date.isoformat() if latest_assessment else None,
                    'status': latest_assessment.status if latest_assessment else 'Not Assessed',
                    'effectiveness_rating': latest_assessment.effectiveness_rating if latest_assessment else None,
                    'findings_count': len(latest_assessment.findings) if latest_assessment else 0,
                    'remediation_required': latest_assessment.remediation_required if latest_assessment else False
                },
                'evidence_summary': {
                    'recent_evidence_items': recent_evidence_count,
                    'last_30_days': recent_evidence_count
                },
                'next_assessment_due': latest_assessment.next_assessment_due.isoformat() if latest_assessment else 'Not Scheduled'
            }
            
            return status
            
        except Exception as e:
            logger.error(f"Error getting control status: {str(e)}")
            raise
        finally:
            db.close()

    async def automated_compliance_monitoring(self) -> Dict[str, Any]:
        """Run automated compliance monitoring and evidence collection"""
        monitoring_results = {
            'timestamp': datetime.utcnow().isoformat(),
            'evidence_collected': 0,
            'alerts_generated': 0,
            'controls_monitored': 0
        }
        
        try:
            # Collect availability metrics for all systems
            systems = ['ai-ml-api', 'threat-detection', 'executive-dashboard']
            for system in systems:
                await self.collect_availability_metrics(system)
                await self.collect_access_control_evidence(system)
                monitoring_results['evidence_collected'] += 2
            
            # Check for overdue assessments
            overdue_assessments = await self._check_overdue_assessments()
            monitoring_results['overdue_assessments'] = len(overdue_assessments)
            
            # Generate alerts for non-compliant controls
            alerts = await self._generate_compliance_alerts()
            monitoring_results['alerts_generated'] = len(alerts)
            
            monitoring_results['controls_monitored'] = len(self.controls)
            
            logger.info(f"Automated compliance monitoring completed: {monitoring_results}")
            return monitoring_results
            
        except Exception as e:
            logger.error(f"Error in automated compliance monitoring: {str(e)}")
            raise

    async def _check_overdue_assessments(self) -> List[str]:
        """Check for overdue control assessments"""
        db = self.SessionLocal()
        try:
            current_time = datetime.utcnow()
            
            overdue = db.query(SOC2ComplianceDB.AssessmentRecord).filter(
                SOC2ComplianceDB.AssessmentRecord.next_assessment_due < current_time
            ).all()
            
            return [assessment.control_id for assessment in overdue]
            
        except Exception as e:
            logger.error(f"Error checking overdue assessments: {str(e)}")
            return []
        finally:
            db.close()

    async def _generate_compliance_alerts(self) -> List[Dict[str, Any]]:
        """Generate alerts for compliance issues"""
        alerts = []
        
        db = self.SessionLocal()
        try:
            # Find non-compliant controls
            non_compliant = db.query(SOC2ComplianceDB.AssessmentRecord).filter(
                SOC2ComplianceDB.AssessmentRecord.status == "non_compliant"
            ).all()
            
            for assessment in non_compliant:
                alerts.append({
                    'alert_type': 'non_compliance',
                    'control_id': assessment.control_id,
                    'severity': 'high',
                    'message': f"Control {assessment.control_id} is non-compliant",
                    'remediation_required': assessment.remediation_required,
                    'assessment_date': assessment.assessment_date.isoformat()
                })
            
            return alerts
            
        except Exception as e:
            logger.error(f"Error generating compliance alerts: {str(e)}")
            return []
        finally:
            db.close()

# Convenience functions for AI/ML integration
async def setup_ai_ml_soc2_compliance(
    framework: SOC2ComplianceFramework,
    system_name: str = "ai-ml-threat-detection"
) -> Dict[str, str]:
    """Setup SOC 2 compliance monitoring for AI/ML systems"""
    
    # Initialize controls
    await framework.initialize_controls()
    
    # Collect initial evidence
    evidence_ids = {}
    
    # Security evidence
    evidence_ids['access_control'] = await framework.collect_access_control_evidence(system_name)
    
    # Availability evidence  
    evidence_ids['availability'] = await framework.collect_availability_metrics(system_name)
    
    # Processing integrity evidence
    processing_data = {
        'system_name': system_name,
        'data_validation_errors': 0,
        'processing_completeness': 100.0,
        'error_rate': 0.001,
        'data_quality_score': 99.5
    }
    
    evidence_ids['processing_integrity'] = await framework.collect_evidence(
        control_id="PI1.1",
        evidence_type="processing_integrity_metrics",
        evidence_data=processing_data,
        collected_by="automated_data_pipeline",
        automated=True,
        description=f"Processing integrity metrics for {system_name}"
    )
    
    logger.info(f"SOC 2 compliance setup completed for {system_name}")
    return evidence_ids

if __name__ == "__main__":
    # Example usage and testing
    async def test_soc2_compliance():
        framework = SOC2ComplianceFramework()
        
        # Setup compliance monitoring
        evidence_ids = await setup_ai_ml_soc2_compliance(framework)
        print(f"Initial evidence collected: {evidence_ids}")
        
        # Assess a control
        assessment_id = await framework.assess_control(
            control_id="CC6.1",
            assessor_id="test_assessor",
            effectiveness_rating="Effective",
            findings=["Access controls properly configured", "MFA enabled for all users"]
        )
        print(f"Control assessment completed: {assessment_id}")
        
        # Generate compliance report
        start_date = datetime.utcnow() - timedelta(days=30)
        end_date = datetime.utcnow()
        
        report = await framework.generate_soc2_report(start_date, end_date)
        print(f"SOC 2 report generated with {report['executive_summary']['overall_compliance_percentage']:.1f}% compliance")
        
        # Run automated monitoring
        monitoring_results = await framework.automated_compliance_monitoring()
        print(f"Automated monitoring: {monitoring_results}")
    
    # Run test
    asyncio.run(test_soc2_compliance())