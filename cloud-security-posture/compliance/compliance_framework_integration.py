#!/usr/bin/env python3
"""
iSECTECH Cloud Security Posture Management - Compliance Framework Integration
Comprehensive compliance reporting and framework integration for security posture management
"""

import asyncio
import json
import logging
import yaml
from collections import defaultdict, Counter
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Any, Set, Union, Tuple

import jinja2
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet


class ComplianceStatus(Enum):
    """Compliance status levels"""
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    PARTIALLY_COMPLIANT = "partially_compliant"
    NOT_APPLICABLE = "not_applicable"
    UNKNOWN = "unknown"


class ComplianceFramework(Enum):
    """Supported compliance frameworks"""
    CIS_AWS_FOUNDATIONS = "cis_aws_foundations_1.4"
    CIS_AZURE_FOUNDATIONS = "cis_azure_foundations_1.3"
    CIS_GCP_FOUNDATIONS = "cis_gcp_foundations_1.3"
    NIST_CSF = "nist_cybersecurity_framework"
    NIST_800_53 = "nist_800_53"
    SOC2_TYPE2 = "soc2_type2"
    PCI_DSS = "pci_dss_3.2.1"
    HIPAA = "hipaa"
    GDPR = "gdpr"
    ISO_27001 = "iso_27001"
    FedRAMP = "fedramp"
    CUSTOM = "custom"


class ReportFormat(Enum):
    """Report output formats"""
    JSON = "json"
    HTML = "html"
    PDF = "pdf"
    CSV = "csv"
    EXCEL = "excel"


@dataclass
class ComplianceControl:
    """Individual compliance control definition"""
    control_id: str
    framework: ComplianceFramework
    title: str
    description: str
    control_family: str
    severity: str = "medium"
    implementation_guidance: str = ""
    testing_procedures: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    applicable_resources: List[str] = field(default_factory=list)
    automated_checks: List[str] = field(default_factory=list)
    manual_checks: List[str] = field(default_factory=list)
    tags: Dict[str, str] = field(default_factory=dict)


@dataclass
class ComplianceEvidence:
    """Evidence for compliance control assessment"""
    evidence_id: str
    control_id: str
    resource_id: str
    resource_type: str
    cloud_provider: str
    account_id: str
    evidence_type: str  # automated, manual, documentation
    status: ComplianceStatus
    findings: List[str] = field(default_factory=list)
    evidence_data: Dict[str, Any] = field(default_factory=dict)
    assessment_timestamp: datetime = field(default_factory=datetime.utcnow)
    assessed_by: Optional[str] = None
    notes: Optional[str] = None
    remediation_required: bool = False
    next_assessment_date: Optional[datetime] = None


@dataclass
class ComplianceAssessment:
    """Complete compliance assessment result"""
    assessment_id: str
    framework: ComplianceFramework
    cloud_provider: str
    account_id: str
    region: str
    assessment_timestamp: datetime
    assessment_period_start: datetime
    assessment_period_end: datetime
    total_controls: int
    assessed_controls: int
    compliant_controls: int
    non_compliant_controls: int
    partially_compliant_controls: int
    not_applicable_controls: int
    compliance_score: float
    control_results: Dict[str, ComplianceEvidence] = field(default_factory=dict)
    summary_by_family: Dict[str, Dict[str, int]] = field(default_factory=dict)
    high_priority_findings: List[str] = field(default_factory=list)
    recommendations: List[Dict[str, Any]] = field(default_factory=list)
    assessor: Optional[str] = None
    approved_by: Optional[str] = None
    approval_timestamp: Optional[datetime] = None


@dataclass
class ComplianceReport:
    """Comprehensive compliance report"""
    report_id: str
    title: str
    frameworks: List[ComplianceFramework]
    cloud_providers: List[str]
    assessment_results: List[ComplianceAssessment]
    executive_summary: Dict[str, Any]
    detailed_findings: List[Dict[str, Any]]
    remediation_plan: List[Dict[str, Any]]
    generated_timestamp: datetime
    generated_by: str
    report_period_start: datetime
    report_period_end: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)


class ComplianceFrameworkIntegration:
    """Main compliance framework integration and reporting engine"""
    
    def __init__(self, config_path: str = "/etc/nsm/compliance_framework.yaml"):
        self.config_path = config_path
        self.config = self._load_config()
        self.logger = self._setup_logging()
        
        # Load compliance controls and frameworks
        self.controls: Dict[str, ComplianceControl] = {}
        self.frameworks: Dict[ComplianceFramework, Dict[str, Any]] = {}
        self._load_compliance_frameworks()
        
        # Assessment storage
        self.assessments: List[ComplianceAssessment] = []
        self.evidence: List[ComplianceEvidence] = []
        
        # Report templates
        self.template_engine = jinja2.Environment(
            loader=jinja2.FileSystemLoader('/etc/nsm/templates'),
            autoescape=True
        )
        
        # Integration with other CSPM components
        self.security_findings = []  # Would be populated from other engines
        self.iam_violations = []
        self.network_violations = []
        self.drift_detections = []
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration"""
        try:
            with open(self.config_path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            print(f"Error loading config: {e}, using defaults")
            return {
                'enabled_frameworks': [
                    'cis_aws_foundations_1.4',
                    'nist_cybersecurity_framework',
                    'soc2_type2'
                ],
                'assessment_schedule': '0 6 * * 1',  # Weekly on Monday at 6 AM
                'auto_generate_reports': True,
                'report_retention_days': 365,
                'email_notifications': True,
                'dashboard_integration': True
            }
    
    def _setup_logging(self) -> logging.Logger:
        """Setup logging"""
        logger = logging.getLogger('ComplianceFrameworkIntegration')
        logger.setLevel(logging.INFO)
        
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        
        return logger
    
    def _load_compliance_frameworks(self):
        """Load compliance framework definitions and controls"""
        
        # CIS AWS Foundations 1.4
        cis_aws_controls = [
            ComplianceControl(
                control_id="1.1",
                framework=ComplianceFramework.CIS_AWS_FOUNDATIONS,
                title="Maintain current contact details",
                description="Ensure contact email and telephone details for AWS account are current",
                control_family="Identity and Access Management",
                severity="medium",
                implementation_guidance="Regularly review and update account contact information",
                testing_procedures=["Review AWS account contact details quarterly"],
                automated_checks=["account_contact_info_check"],
                applicable_resources=["aws_account"]
            ),
            ComplianceControl(
                control_id="1.3",
                framework=ComplianceFramework.CIS_AWS_FOUNDATIONS,
                title="Ensure credentials unused for 90 days or greater are disabled",
                description="AWS IAM users can access AWS resources using different types of credentials",
                control_family="Identity and Access Management",
                severity="high",
                implementation_guidance="Implement automated credential rotation and monitoring",
                testing_procedures=["Review IAM credential usage reports monthly"],
                automated_checks=["iam_unused_credentials_check"],
                applicable_resources=["iam_user", "iam_access_key"]
            ),
            ComplianceControl(
                control_id="2.1.1",
                framework=ComplianceFramework.CIS_AWS_FOUNDATIONS,
                title="Ensure S3 bucket access logging is enabled",
                description="S3 Bucket access logging generates a log that contains access records",
                control_family="Logging and Monitoring",
                severity="medium",
                implementation_guidance="Enable S3 access logging for all buckets containing sensitive data",
                testing_procedures=["Verify S3 access logging configuration quarterly"],
                automated_checks=["s3_access_logging_check"],
                applicable_resources=["s3_bucket"]
            ),
            ComplianceControl(
                control_id="2.1.3",
                framework=ComplianceFramework.CIS_AWS_FOUNDATIONS,
                title="Ensure S3 bucket public access block is enabled",
                description="Amazon S3 provides Block Public Access settings for buckets and accounts",
                control_family="Data Protection",
                severity="critical",
                implementation_guidance="Enable all four public access block settings",
                testing_procedures=["Verify public access block settings monthly"],
                automated_checks=["s3_public_access_block_check"],
                applicable_resources=["s3_bucket"]
            ),
            ComplianceControl(
                control_id="4.1",
                framework=ComplianceFramework.CIS_AWS_FOUNDATIONS,
                title="Ensure no security groups allow ingress from 0.0.0.0/0 to port 22",
                description="Security groups provide stateful filtering of ingress/egress network traffic",
                control_family="Network Security",
                severity="critical",
                implementation_guidance="Remove or restrict overly permissive SSH access rules",
                testing_procedures=["Review security group rules weekly"],
                automated_checks=["security_group_ssh_check"],
                applicable_resources=["security_group"]
            )
        ]
        
        # SOC 2 Type II Controls
        soc2_controls = [
            ComplianceControl(
                control_id="CC6.1",
                framework=ComplianceFramework.SOC2_TYPE2,
                title="Logical and Physical Access Controls",
                description="The entity implements logical and physical access controls to protect against threats",
                control_family="Access Controls",
                severity="high",
                implementation_guidance="Implement multi-factor authentication and role-based access controls",
                testing_procedures=["Review access controls quarterly", "Test MFA implementation"],
                automated_checks=["mfa_enabled_check", "rbac_implementation_check"]
            ),
            ComplianceControl(
                control_id="CC6.7",
                framework=ComplianceFramework.SOC2_TYPE2,
                title="Data Transmission and Disposal",
                description="The entity restricts the transmission, movement, and removal of information",
                control_family="Data Protection",
                severity="high",
                implementation_guidance="Encrypt data in transit and at rest, implement secure disposal procedures",
                testing_procedures=["Verify encryption implementation", "Test data disposal procedures"],
                automated_checks=["encryption_in_transit_check", "encryption_at_rest_check"]
            ),
            ComplianceControl(
                control_id="CC7.1",
                framework=ComplianceFramework.SOC2_TYPE2,
                title="System Operations",
                description="The entity ensures authorized users can access the system",
                control_family="System Operations",
                severity="medium",
                implementation_guidance="Implement system monitoring and availability controls",
                testing_procedures=["Monitor system availability", "Test incident response procedures"],
                automated_checks=["system_availability_check", "monitoring_enabled_check"]
            )
        ]
        
        # NIST Cybersecurity Framework
        nist_csf_controls = [
            ComplianceControl(
                control_id="ID.AM-1",
                framework=ComplianceFramework.NIST_CSF,
                title="Physical devices and systems within the organization are inventoried",
                description="Maintain an accurate inventory of physical devices and systems",
                control_family="Asset Management",
                severity="medium",
                implementation_guidance="Implement automated asset discovery and inventory management",
                testing_procedures=["Verify asset inventory accuracy quarterly"],
                automated_checks=["asset_inventory_check"]
            ),
            ComplianceControl(
                control_id="PR.AC-1",
                framework=ComplianceFramework.NIST_CSF,
                title="Identities and credentials are issued, managed, verified, revoked, and audited",
                description="Implement comprehensive identity and credential management",
                control_family="Access Control",
                severity="high",
                implementation_guidance="Deploy identity management system with automated provisioning",
                testing_procedures=["Audit identity lifecycle management monthly"],
                automated_checks=["identity_management_check", "credential_lifecycle_check"]
            ),
            ComplianceControl(
                control_id="PR.DS-1",
                framework=ComplianceFramework.NIST_CSF,
                title="Data-at-rest is protected",
                description="Implement appropriate protection measures for data at rest",
                control_family="Data Security",
                severity="high",
                implementation_guidance="Enable encryption for all data storage systems",
                testing_procedures=["Verify encryption implementation quarterly"],
                automated_checks=["data_at_rest_encryption_check"]
            )
        ]
        
        # Store all controls
        all_controls = cis_aws_controls + soc2_controls + nist_csf_controls
        for control in all_controls:
            self.controls[f"{control.framework.value}_{control.control_id}"] = control
        
        # Framework metadata
        self.frameworks = {
            ComplianceFramework.CIS_AWS_FOUNDATIONS: {
                'name': 'CIS Amazon Web Services Foundations Benchmark',
                'version': '1.4.0',
                'description': 'Security configuration best practices for AWS',
                'categories': ['Identity and Access Management', 'Logging and Monitoring', 'Network Security', 'Data Protection'],
                'total_controls': len([c for c in all_controls if c.framework == ComplianceFramework.CIS_AWS_FOUNDATIONS])
            },
            ComplianceFramework.SOC2_TYPE2: {
                'name': 'SOC 2 Type II',
                'version': '2017',
                'description': 'Service Organization Control 2 Type II compliance framework',
                'categories': ['Access Controls', 'Data Protection', 'System Operations', 'Change Management'],
                'total_controls': len([c for c in all_controls if c.framework == ComplianceFramework.SOC2_TYPE2])
            },
            ComplianceFramework.NIST_CSF: {
                'name': 'NIST Cybersecurity Framework',
                'version': '1.1',
                'description': 'Framework for improving critical infrastructure cybersecurity',
                'categories': ['Identify', 'Protect', 'Detect', 'Respond', 'Recover'],
                'total_controls': len([c for c in all_controls if c.framework == ComplianceFramework.NIST_CSF])
            }
        }
        
        self.logger.info(f"Loaded {len(self.controls)} compliance controls across {len(self.frameworks)} frameworks")
    
    async def assess_compliance(self, framework: ComplianceFramework, cloud_provider: str,
                               account_id: str, region: str = "global") -> ComplianceAssessment:
        """Perform comprehensive compliance assessment"""
        
        start_time = datetime.utcnow()
        self.logger.info(f"Starting {framework.value} compliance assessment for {cloud_provider} account {account_id}")
        
        # Get applicable controls for this framework
        framework_controls = [
            control for control in self.controls.values()
            if control.framework == framework
        ]
        
        assessment = ComplianceAssessment(
            assessment_id=f"assessment_{framework.value}_{cloud_provider}_{account_id}_{int(start_time.timestamp())}",
            framework=framework,
            cloud_provider=cloud_provider,
            account_id=account_id,
            region=region,
            assessment_timestamp=start_time,
            assessment_period_start=start_time - timedelta(days=30),  # 30-day assessment period
            assessment_period_end=start_time,
            total_controls=len(framework_controls),
            assessed_controls=0,
            compliant_controls=0,
            non_compliant_controls=0,
            partially_compliant_controls=0,
            not_applicable_controls=0,
            compliance_score=0.0
        )
        
        # Assess each control
        for control in framework_controls:
            try:
                evidence = await self._assess_control(control, cloud_provider, account_id, region)
                
                if evidence:
                    assessment.control_results[control.control_id] = evidence
                    assessment.assessed_controls += 1
                    
                    # Update counters based on compliance status
                    if evidence.status == ComplianceStatus.COMPLIANT:
                        assessment.compliant_controls += 1
                    elif evidence.status == ComplianceStatus.NON_COMPLIANT:
                        assessment.non_compliant_controls += 1
                    elif evidence.status == ComplianceStatus.PARTIALLY_COMPLIANT:
                        assessment.partially_compliant_controls += 1
                    elif evidence.status == ComplianceStatus.NOT_APPLICABLE:
                        assessment.not_applicable_controls += 1
                    
                    # Track high-priority findings
                    if (evidence.status == ComplianceStatus.NON_COMPLIANT and 
                        control.severity in ['high', 'critical']):
                        assessment.high_priority_findings.append(control.control_id)
            
            except Exception as e:
                self.logger.error(f"Error assessing control {control.control_id}: {e}")
        
        # Calculate compliance score
        assessed_controls = assessment.assessed_controls - assessment.not_applicable_controls
        if assessed_controls > 0:
            compliant_score = assessment.compliant_controls + (assessment.partially_compliant_controls * 0.5)
            assessment.compliance_score = (compliant_score / assessed_controls) * 100
        
        # Generate summary by control family
        assessment.summary_by_family = self._generate_family_summary(assessment.control_results, framework_controls)
        
        # Generate recommendations
        assessment.recommendations = self._generate_compliance_recommendations(assessment)
        
        # Store assessment
        self.assessments.append(assessment)
        
        self.logger.info(f"Compliance assessment completed: {assessment.compliance_score:.1f}% compliant")
        
        return assessment
    
    async def _assess_control(self, control: ComplianceControl, cloud_provider: str,
                            account_id: str, region: str) -> Optional[ComplianceEvidence]:
        """Assess individual compliance control"""
        
        evidence = ComplianceEvidence(
            evidence_id=f"evidence_{control.control_id}_{account_id}_{int(datetime.utcnow().timestamp())}",
            control_id=control.control_id,
            resource_id=account_id,  # Default to account ID
            resource_type="account",
            cloud_provider=cloud_provider,
            account_id=account_id,
            evidence_type="automated"
        )
        
        # Perform automated checks if available
        if control.automated_checks:
            compliance_status, findings = await self._run_automated_checks(
                control.automated_checks, cloud_provider, account_id, region
            )
            evidence.status = compliance_status
            evidence.findings = findings
        else:
            # Default to manual assessment required
            evidence.status = ComplianceStatus.UNKNOWN
            evidence.evidence_type = "manual"
            evidence.findings = ["Manual assessment required"]
        
        # Check for remediation requirements
        if evidence.status == ComplianceStatus.NON_COMPLIANT:
            evidence.remediation_required = True
        
        return evidence
    
    async def _run_automated_checks(self, checks: List[str], cloud_provider: str,
                                   account_id: str, region: str) -> Tuple[ComplianceStatus, List[str]]:
        """Run automated compliance checks"""
        
        findings = []
        overall_status = ComplianceStatus.COMPLIANT
        
        for check in checks:
            try:
                if check == "iam_unused_credentials_check":
                    status, check_findings = await self._check_iam_unused_credentials(cloud_provider, account_id)
                elif check == "s3_access_logging_check":
                    status, check_findings = await self._check_s3_access_logging(cloud_provider, account_id)
                elif check == "s3_public_access_block_check":
                    status, check_findings = await self._check_s3_public_access_block(cloud_provider, account_id)
                elif check == "security_group_ssh_check":
                    status, check_findings = await self._check_security_group_ssh(cloud_provider, account_id, region)
                elif check == "mfa_enabled_check":
                    status, check_findings = await self._check_mfa_enabled(cloud_provider, account_id)
                elif check == "encryption_at_rest_check":
                    status, check_findings = await self._check_encryption_at_rest(cloud_provider, account_id)
                else:
                    self.logger.warning(f"Unknown automated check: {check}")
                    continue
                
                findings.extend(check_findings)
                
                # Update overall status (worst case wins)
                if status == ComplianceStatus.NON_COMPLIANT:
                    overall_status = ComplianceStatus.NON_COMPLIANT
                elif status == ComplianceStatus.PARTIALLY_COMPLIANT and overall_status == ComplianceStatus.COMPLIANT:
                    overall_status = ComplianceStatus.PARTIALLY_COMPLIANT
                
            except Exception as e:
                self.logger.error(f"Error running automated check {check}: {e}")
                findings.append(f"Error running check {check}: {str(e)}")
                if overall_status == ComplianceStatus.COMPLIANT:
                    overall_status = ComplianceStatus.UNKNOWN
        
        return overall_status, findings
    
    async def _check_iam_unused_credentials(self, cloud_provider: str, account_id: str) -> Tuple[ComplianceStatus, List[str]]:
        """Check for unused IAM credentials"""
        # This would integrate with the IAM analysis engine
        # For now, returning a placeholder result
        
        if self.iam_violations:
            unused_creds = [v for v in self.iam_violations if 'unused' in v.get('title', '').lower()]
            if unused_creds:
                return ComplianceStatus.NON_COMPLIANT, [f"Found {len(unused_creds)} unused credentials"]
        
        return ComplianceStatus.COMPLIANT, ["No unused credentials found"]
    
    async def _check_s3_access_logging(self, cloud_provider: str, account_id: str) -> Tuple[ComplianceStatus, List[str]]:
        """Check S3 access logging configuration"""
        # This would integrate with the security configuration engine
        findings = []
        
        if self.security_findings:
            s3_logging_issues = [
                f for f in self.security_findings 
                if 's3' in f.get('resource_type', '').lower() and 'logging' in f.get('title', '').lower()
            ]
            if s3_logging_issues:
                findings = [f"S3 access logging issues found in {len(s3_logging_issues)} buckets"]
                return ComplianceStatus.NON_COMPLIANT, findings
        
        return ComplianceStatus.COMPLIANT, ["S3 access logging properly configured"]
    
    async def _check_s3_public_access_block(self, cloud_provider: str, account_id: str) -> Tuple[ComplianceStatus, List[str]]:
        """Check S3 public access block configuration"""
        findings = []
        
        if self.security_findings:
            s3_public_issues = [
                f for f in self.security_findings 
                if 's3' in f.get('resource_type', '').lower() and 'public' in f.get('title', '').lower()
            ]
            if s3_public_issues:
                findings = [f"S3 public access issues found in {len(s3_public_issues)} buckets"]
                return ComplianceStatus.NON_COMPLIANT, findings
        
        return ComplianceStatus.COMPLIANT, ["S3 public access properly blocked"]
    
    async def _check_security_group_ssh(self, cloud_provider: str, account_id: str, region: str) -> Tuple[ComplianceStatus, List[str]]:
        """Check security group SSH access"""
        findings = []
        
        if self.network_violations:
            ssh_violations = [
                v for v in self.network_violations 
                if 'ssh' in v.get('title', '').lower() or '22' in str(v.get('description', ''))
            ]
            if ssh_violations:
                findings = [f"Found {len(ssh_violations)} security groups with unrestricted SSH access"]
                return ComplianceStatus.NON_COMPLIANT, findings
        
        return ComplianceStatus.COMPLIANT, ["No unrestricted SSH access found"]
    
    async def _check_mfa_enabled(self, cloud_provider: str, account_id: str) -> Tuple[ComplianceStatus, List[str]]:
        """Check MFA enablement"""
        # Placeholder implementation
        return ComplianceStatus.PARTIALLY_COMPLIANT, ["MFA enabled for some users, not all"]
    
    async def _check_encryption_at_rest(self, cloud_provider: str, account_id: str) -> Tuple[ComplianceStatus, List[str]]:
        """Check encryption at rest"""
        findings = []
        
        if self.security_findings:
            encryption_issues = [
                f for f in self.security_findings 
                if 'encryption' in f.get('title', '').lower()
            ]
            if encryption_issues:
                findings = [f"Encryption issues found in {len(encryption_issues)} resources"]
                return ComplianceStatus.NON_COMPLIANT, findings
        
        return ComplianceStatus.COMPLIANT, ["Encryption at rest properly configured"]
    
    def _generate_family_summary(self, control_results: Dict[str, ComplianceEvidence],
                                framework_controls: List[ComplianceControl]) -> Dict[str, Dict[str, int]]:
        """Generate summary by control family"""
        
        family_summary = defaultdict(lambda: defaultdict(int))
        
        for control in framework_controls:
            family = control.control_family
            evidence = control_results.get(control.control_id)
            
            if evidence:
                status = evidence.status.value
                family_summary[family][status] += 1
                family_summary[family]['total'] += 1
        
        return dict(family_summary)
    
    def _generate_compliance_recommendations(self, assessment: ComplianceAssessment) -> List[Dict[str, Any]]:
        """Generate compliance recommendations"""
        
        recommendations = []
        
        # High priority findings
        if assessment.high_priority_findings:
            recommendations.append({
                'priority': 'critical',
                'category': 'immediate_action',
                'title': f'Address {len(assessment.high_priority_findings)} high-priority compliance failures',
                'description': 'Critical compliance controls are failing and require immediate attention',
                'impact': 'High risk of regulatory violations and audit findings',
                'controls': assessment.high_priority_findings[:5]
            })
        
        # Overall compliance score
        if assessment.compliance_score < 80:
            recommendations.append({
                'priority': 'high',
                'category': 'compliance_improvement',
                'title': f'Improve overall compliance score ({assessment.compliance_score:.1f}%)',
                'description': 'Compliance score is below acceptable threshold',
                'impact': 'Risk of failing compliance audits',
                'target_score': 90.0
            })
        
        # Control family-specific recommendations
        for family, summary in assessment.summary_by_family.items():
            non_compliant = summary.get('non_compliant', 0)
            total = summary.get('total', 0)
            
            if non_compliant > 0 and total > 0:
                family_score = ((total - non_compliant) / total) * 100
                if family_score < 80:
                    recommendations.append({
                        'priority': 'medium',
                        'category': 'control_family',
                        'title': f'Improve {family} compliance ({family_score:.1f}%)',
                        'description': f'{non_compliant} out of {total} controls are non-compliant',
                        'impact': f'Weakened {family.lower()} security posture',
                        'family': family
                    })
        
        # General recommendations
        if assessment.assessed_controls < assessment.total_controls:
            missing_assessments = assessment.total_controls - assessment.assessed_controls
            recommendations.append({
                'priority': 'medium',
                'category': 'assessment_coverage',
                'title': f'Complete assessment for {missing_assessments} remaining controls',
                'description': 'Some controls require manual assessment or additional tooling',
                'impact': 'Incomplete compliance visibility'
            })
        
        return recommendations
    
    async def generate_compliance_report(self, frameworks: List[ComplianceFramework],
                                       cloud_providers: List[str], 
                                       output_format: ReportFormat = ReportFormat.HTML,
                                       report_title: str = None) -> ComplianceReport:
        """Generate comprehensive compliance report"""
        
        start_time = datetime.utcnow()
        
        # Get relevant assessments
        relevant_assessments = [
            assessment for assessment in self.assessments
            if (assessment.framework in frameworks and 
                assessment.cloud_provider in cloud_providers)
        ]
        
        if not relevant_assessments:
            raise ValueError("No assessment data available for specified criteria")
        
        # Generate executive summary
        executive_summary = self._generate_executive_summary(relevant_assessments)
        
        # Generate detailed findings
        detailed_findings = self._generate_detailed_findings(relevant_assessments)
        
        # Generate remediation plan
        remediation_plan = self._generate_remediation_plan(relevant_assessments)
        
        report = ComplianceReport(
            report_id=f"compliance_report_{int(start_time.timestamp())}",
            title=report_title or f"Compliance Report - {start_time.strftime('%Y-%m-%d')}",
            frameworks=frameworks,
            cloud_providers=cloud_providers,
            assessment_results=relevant_assessments,
            executive_summary=executive_summary,
            detailed_findings=detailed_findings,
            remediation_plan=remediation_plan,
            generated_timestamp=start_time,
            generated_by="iSECTECH CSPM System",
            report_period_start=min(a.assessment_period_start for a in relevant_assessments),
            report_period_end=max(a.assessment_period_end for a in relevant_assessments)
        )
        
        self.logger.info(f"Generated compliance report {report.report_id}")
        
        return report
    
    def _generate_executive_summary(self, assessments: List[ComplianceAssessment]) -> Dict[str, Any]:
        """Generate executive summary"""
        
        total_controls = sum(a.total_controls for a in assessments)
        total_compliant = sum(a.compliant_controls for a in assessments)
        total_non_compliant = sum(a.non_compliant_controls for a in assessments)
        total_assessed = sum(a.assessed_controls for a in assessments)
        
        overall_score = 0.0
        if total_assessed > 0:
            overall_score = (total_compliant / total_assessed) * 100
        
        # Risk assessment
        risk_level = "Low"
        if overall_score < 60:
            risk_level = "Critical"
        elif overall_score < 75:
            risk_level = "High"
        elif overall_score < 85:
            risk_level = "Medium"
        
        return {
            'overall_compliance_score': overall_score,
            'total_controls_assessed': total_assessed,
            'compliant_controls': total_compliant,
            'non_compliant_controls': total_non_compliant,
            'risk_level': risk_level,
            'frameworks_assessed': len(set(a.framework for a in assessments)),
            'cloud_providers_assessed': len(set(a.cloud_provider for a in assessments)),
            'high_priority_findings': sum(len(a.high_priority_findings) for a in assessments),
            'key_recommendations': self._get_top_recommendations(assessments)
        }
    
    def _generate_detailed_findings(self, assessments: List[ComplianceAssessment]) -> List[Dict[str, Any]]:
        """Generate detailed findings"""
        
        findings = []
        
        for assessment in assessments:
            for control_id, evidence in assessment.control_results.items():
                if evidence.status == ComplianceStatus.NON_COMPLIANT:
                    control = self.controls.get(f"{assessment.framework.value}_{control_id}")
                    
                    finding = {
                        'framework': assessment.framework.value,
                        'control_id': control_id,
                        'control_title': control.title if control else "Unknown",
                        'severity': control.severity if control else "medium",
                        'cloud_provider': assessment.cloud_provider,
                        'account_id': assessment.account_id,
                        'status': evidence.status.value,
                        'findings': evidence.findings,
                        'remediation_required': evidence.remediation_required,
                        'assessment_date': evidence.assessment_timestamp.isoformat()
                    }
                    findings.append(finding)
        
        # Sort by severity and framework
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        findings.sort(key=lambda x: (severity_order.get(x['severity'], 4), x['framework'], x['control_id']))
        
        return findings
    
    def _generate_remediation_plan(self, assessments: List[ComplianceAssessment]) -> List[Dict[str, Any]]:
        """Generate remediation plan"""
        
        remediation_items = []
        
        # Collect all recommendations
        all_recommendations = []
        for assessment in assessments:
            all_recommendations.extend(assessment.recommendations)
        
        # Group by priority and category
        priority_groups = defaultdict(list)
        for rec in all_recommendations:
            priority_groups[rec['priority']].append(rec)
        
        # Create remediation plan
        for priority in ['critical', 'high', 'medium', 'low']:
            if priority in priority_groups:
                for rec in priority_groups[priority]:
                    remediation_item = {
                        'priority': priority,
                        'category': rec['category'],
                        'title': rec['title'],
                        'description': rec['description'],
                        'estimated_effort': self._estimate_remediation_effort(rec),
                        'timeline': self._suggest_remediation_timeline(priority),
                        'responsible_team': self._identify_responsible_team(rec['category']),
                        'dependencies': [],
                        'success_criteria': self._define_success_criteria(rec)
                    }
                    remediation_items.append(remediation_item)
        
        return remediation_items
    
    def _get_top_recommendations(self, assessments: List[ComplianceAssessment]) -> List[str]:
        """Get top recommendations across all assessments"""
        
        all_recommendations = []
        for assessment in assessments:
            all_recommendations.extend(assessment.recommendations)
        
        # Group by title and count frequency
        rec_counter = Counter(rec['title'] for rec in all_recommendations)
        
        # Return top 5 most common recommendations
        return [title for title, _ in rec_counter.most_common(5)]
    
    def _estimate_remediation_effort(self, recommendation: Dict[str, Any]) -> str:
        """Estimate remediation effort"""
        
        category = recommendation.get('category', '')
        
        if 'immediate_action' in category:
            return "High (2-4 weeks)"
        elif 'compliance_improvement' in category:
            return "Medium (1-2 weeks)"
        elif 'control_family' in category:
            return "Medium (1-3 weeks)"
        else:
            return "Low (1-5 days)"
    
    def _suggest_remediation_timeline(self, priority: str) -> str:
        """Suggest remediation timeline based on priority"""
        
        timelines = {
            'critical': 'Immediate (1-3 days)',
            'high': 'Short-term (1-2 weeks)',
            'medium': 'Medium-term (2-4 weeks)',
            'low': 'Long-term (1-2 months)'
        }
        
        return timelines.get(priority, 'Medium-term (2-4 weeks)')
    
    def _identify_responsible_team(self, category: str) -> str:
        """Identify responsible team based on category"""
        
        team_mapping = {
            'immediate_action': 'Security Team',
            'compliance_improvement': 'Compliance Team',
            'control_family': 'Platform Team',
            'assessment_coverage': 'Security Team',
            'automation': 'DevOps Team'
        }
        
        return team_mapping.get(category, 'Security Team')
    
    def _define_success_criteria(self, recommendation: Dict[str, Any]) -> str:
        """Define success criteria for remediation"""
        
        category = recommendation.get('category', '')
        
        if 'compliance_improvement' in category:
            target_score = recommendation.get('target_score', 90)
            return f"Achieve compliance score of {target_score}% or higher"
        elif 'immediate_action' in category:
            return "All high-priority findings resolved"
        elif 'control_family' in category:
            return "All controls in family achieve compliant status"
        else:
            return "Remediation actions completed successfully"
    
    def export_report(self, report: ComplianceReport, output_format: ReportFormat, output_path: str = None) -> str:
        """Export compliance report in specified format"""
        
        if output_format == ReportFormat.JSON:
            content = json.dumps(asdict(report), indent=2, default=str)
            extension = '.json'
        
        elif output_format == ReportFormat.HTML:
            content = self._generate_html_report(report)
            extension = '.html'
        
        elif output_format == ReportFormat.CSV:
            content = self._generate_csv_report(report)
            extension = '.csv'
        
        elif output_format == ReportFormat.PDF:
            content = self._generate_pdf_report(report)
            extension = '.pdf'
        
        else:
            raise ValueError(f"Unsupported output format: {output_format}")
        
        # Save to file if path provided
        if output_path:
            file_path = Path(output_path)
            if not file_path.suffix:
                file_path = file_path.with_suffix(extension)
            
            if output_format == ReportFormat.PDF:
                with open(file_path, 'wb') as f:
                    f.write(content)
            else:
                with open(file_path, 'w') as f:
                    f.write(content)
            
            self.logger.info(f"Report exported to {file_path}")
            return str(file_path)
        
        return content
    
    def _generate_html_report(self, report: ComplianceReport) -> str:
        """Generate HTML compliance report"""
        
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>{{ report.title }}</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                .header { background-color: #2c3e50; color: white; padding: 20px; border-radius: 5px; }
                .summary { background-color: #ecf0f1; padding: 15px; margin: 20px 0; border-radius: 5px; }
                .finding { border-left: 4px solid #e74c3c; padding: 10px; margin: 10px 0; background-color: #fdf2f2; }
                .compliant { border-left-color: #27ae60; background-color: #f2fdf2; }
                .metric { display: inline-block; margin: 10px; padding: 15px; background-color: #3498db; color: white; border-radius: 3px; }
                table { width: 100%; border-collapse: collapse; margin: 20px 0; }
                th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                th { background-color: #f2f2f2; }
                .critical { color: #e74c3c; font-weight: bold; }
                .high { color: #f39c12; font-weight: bold; }
                .medium { color: #f1c40f; }
                .low { color: #95a5a6; }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>{{ report.title }}</h1>
                <p>Generated: {{ report.generated_timestamp.strftime('%Y-%m-%d %H:%M:%S') }}</p>
                <p>Report Period: {{ report.report_period_start.strftime('%Y-%m-%d') }} to {{ report.report_period_end.strftime('%Y-%m-%d') }}</p>
            </div>
            
            <div class="summary">
                <h2>Executive Summary</h2>
                <div class="metric">Overall Score: {{ "%.1f"|format(report.executive_summary.overall_compliance_score) }}%</div>
                <div class="metric">Risk Level: {{ report.executive_summary.risk_level }}</div>
                <div class="metric">Total Controls: {{ report.executive_summary.total_controls_assessed }}</div>
                <div class="metric">Non-Compliant: {{ report.executive_summary.non_compliant_controls }}</div>
            </div>
            
            <h2>Assessment Results by Framework</h2>
            <table>
                <tr>
                    <th>Framework</th>
                    <th>Cloud Provider</th>
                    <th>Compliance Score</th>
                    <th>Compliant</th>
                    <th>Non-Compliant</th>
                    <th>Status</th>
                </tr>
                {% for assessment in report.assessment_results %}
                <tr>
                    <td>{{ assessment.framework.value }}</td>
                    <td>{{ assessment.cloud_provider }}</td>
                    <td>{{ "%.1f"|format(assessment.compliance_score) }}%</td>
                    <td>{{ assessment.compliant_controls }}</td>
                    <td>{{ assessment.non_compliant_controls }}</td>
                    <td>{% if assessment.compliance_score >= 80 %}<span class="compliant">✓</span>{% else %}<span class="critical">✗</span>{% endif %}</td>
                </tr>
                {% endfor %}
            </table>
            
            <h2>High Priority Findings</h2>
            {% for finding in report.detailed_findings[:10] %}
            <div class="finding">
                <h4 class="{{ finding.severity }}">{{ finding.control_title }}</h4>
                <p><strong>Framework:</strong> {{ finding.framework }} | <strong>Control:</strong> {{ finding.control_id }}</p>
                <p><strong>Cloud Provider:</strong> {{ finding.cloud_provider }}</p>
                <ul>
                {% for issue in finding.findings %}
                    <li>{{ issue }}</li>
                {% endfor %}
                </ul>
            </div>
            {% endfor %}
            
            <h2>Remediation Plan</h2>
            <table>
                <tr>
                    <th>Priority</th>
                    <th>Title</th>
                    <th>Timeline</th>
                    <th>Responsible Team</th>
                    <th>Effort</th>
                </tr>
                {% for item in report.remediation_plan[:15] %}
                <tr>
                    <td><span class="{{ item.priority }}">{{ item.priority.title() }}</span></td>
                    <td>{{ item.title }}</td>
                    <td>{{ item.timeline }}</td>
                    <td>{{ item.responsible_team }}</td>
                    <td>{{ item.estimated_effort }}</td>
                </tr>
                {% endfor %}
            </table>
        </body>
        </html>
        """
        
        template = self.template_engine.from_string(html_template)
        return template.render(report=report)
    
    def _generate_csv_report(self, report: ComplianceReport) -> str:
        """Generate CSV compliance report"""
        
        import csv
        import io
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow([
            'Framework', 'Control ID', 'Control Title', 'Severity', 
            'Cloud Provider', 'Account ID', 'Status', 'Assessment Date'
        ])
        
        # Write findings
        for finding in report.detailed_findings:
            writer.writerow([
                finding['framework'],
                finding['control_id'],
                finding['control_title'],
                finding['severity'],
                finding['cloud_provider'],
                finding['account_id'],
                finding['status'],
                finding['assessment_date']
            ])
        
        return output.getvalue()
    
    def _generate_pdf_report(self, report: ComplianceReport) -> bytes:
        """Generate PDF compliance report"""
        
        # This is a simplified PDF generation
        # In production, you'd use a more sophisticated PDF library
        
        import io
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.lib.pagesizes import letter
        from reportlab.lib import colors
        
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        styles = getSampleStyleSheet()
        story = []
        
        # Title
        title = Paragraph(report.title, styles['Title'])
        story.append(title)
        story.append(Spacer(1, 12))
        
        # Executive Summary
        summary_text = f"""
        <b>Executive Summary</b><br/>
        Overall Compliance Score: {report.executive_summary['overall_compliance_score']:.1f}%<br/>
        Risk Level: {report.executive_summary['risk_level']}<br/>
        Total Controls Assessed: {report.executive_summary['total_controls_assessed']}<br/>
        Non-Compliant Controls: {report.executive_summary['non_compliant_controls']}<br/>
        """
        summary = Paragraph(summary_text, styles['Normal'])
        story.append(summary)
        story.append(Spacer(1, 12))
        
        # Assessment Results Table
        assessment_data = [['Framework', 'Cloud Provider', 'Compliance Score', 'Status']]
        for assessment in report.assessment_results:
            status = "✓ Compliant" if assessment.compliance_score >= 80 else "✗ Non-Compliant"
            assessment_data.append([
                assessment.framework.value,
                assessment.cloud_provider,
                f"{assessment.compliance_score:.1f}%",
                status
            ])
        
        assessment_table = Table(assessment_data)
        assessment_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 14),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(assessment_table)
        story.append(Spacer(1, 12))
        
        # Build PDF
        doc.build(story)
        buffer.seek(0)
        
        return buffer.getvalue()


async def main():
    """Main function for testing compliance framework integration"""
    engine = ComplianceFrameworkIntegration()
    
    try:
        print("Compliance Framework Integration initialized successfully")
        print(f"Loaded {len(engine.controls)} compliance controls")
        print(f"Supporting {len(engine.frameworks)} compliance frameworks")
        
        # Example: Run compliance assessment
        # assessment = await engine.assess_compliance(
        #     ComplianceFramework.CIS_AWS_FOUNDATIONS, "aws", "123456789012", "us-east-1"
        # )
        # print(f"Assessment completed: {assessment.compliance_score:.1f}% compliant")
        
        # Example: Generate compliance report
        # report = await engine.generate_compliance_report(
        #     [ComplianceFramework.CIS_AWS_FOUNDATIONS], ["aws"]
        # )
        # print(f"Generated report: {report.report_id}")
        
    except Exception as e:
        print(f"Error running compliance framework integration: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())