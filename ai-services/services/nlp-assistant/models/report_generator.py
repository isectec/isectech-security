"""
Security Report Generator for iSECTECH Platform.

This module provides automated security report generation capabilities
with customizable templates, multi-format output, and compliance-ready
documentation for various stakeholders and regulatory requirements.
"""

import asyncio
import json
import logging
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple, Union

import jinja2
from pydantic import BaseModel, Field, validator

from ...shared.config.settings import SecurityClassification, get_settings
from ...shared.security.audit import AuditLogger
from .security_nlp_processor import SecurityContext, EventCategory, ThreatSeverity
from .threat_explainer import ThreatExplanation, ExplanationStyle
from .investigation_advisor import InvestigationRecommendation, InvestigationComplexity


# Configure logging
logger = logging.getLogger(__name__)


class ReportType(str, Enum):
    """Types of security reports that can be generated."""
    INCIDENT_REPORT = "INCIDENT_REPORT"               # Detailed incident analysis
    EXECUTIVE_SUMMARY = "EXECUTIVE_SUMMARY"           # High-level executive brief
    TECHNICAL_ANALYSIS = "TECHNICAL_ANALYSIS"         # Deep technical details
    COMPLIANCE_REPORT = "COMPLIANCE_REPORT"           # Regulatory compliance
    THREAT_INTELLIGENCE = "THREAT_INTELLIGENCE"       # Threat analysis and IOCs
    INVESTIGATION_PLAN = "INVESTIGATION_PLAN"         # Investigation procedures
    LESSONS_LEARNED = "LESSONS_LEARNED"               # Post-incident analysis
    REGULATORY_NOTIFICATION = "REGULATORY_NOTIFICATION" # Breach notifications
    STAKEHOLDER_COMMUNICATION = "STAKEHOLDER_COMMUNICATION" # Business communication


class ReportFormat(str, Enum):
    """Output formats for generated reports."""
    PDF = "PDF"                   # Portable Document Format
    HTML = "HTML"                 # Web-based format
    MARKDOWN = "MARKDOWN"         # Markdown format
    JSON = "JSON"                 # Structured JSON data
    DOCX = "DOCX"                 # Microsoft Word format
    XML = "XML"                   # Structured XML format


class ReportClassification(str, Enum):
    """Security classification levels for reports."""
    UNCLASSIFIED = "UNCLASSIFIED"
    CONFIDENTIAL = "CONFIDENTIAL"
    SECRET = "SECRET"
    TOP_SECRET = "TOP_SECRET"


class ComplianceFramework(str, Enum):
    """Supported compliance frameworks for reports."""
    GDPR = "GDPR"                 # General Data Protection Regulation
    HIPAA = "HIPAA"               # Health Insurance Portability and Accountability Act
    PCI_DSS = "PCI_DSS"           # Payment Card Industry Data Security Standard
    SOX = "SOX"                   # Sarbanes-Oxley Act
    NIST = "NIST"                 # NIST Cybersecurity Framework
    ISO27001 = "ISO27001"         # ISO 27001 Information Security
    FISMA = "FISMA"               # Federal Information Security Management Act


class ReportSection(BaseModel):
    """Individual report section with content and metadata."""
    
    section_id: str = Field(..., description="Unique section identifier")
    title: str = Field(..., description="Section title")
    content: str = Field(..., description="Section content")
    
    # Section properties
    order: int = Field(..., description="Section display order")
    required: bool = Field(default=True, description="Whether section is required")
    classification: ReportClassification = Field(default=ReportClassification.UNCLASSIFIED)
    
    # Content metadata
    content_type: str = Field(default="text", description="Content type (text, table, chart)")
    formatting: Dict[str, Any] = Field(default_factory=dict, description="Formatting options")
    
    # References and sources
    data_sources: List[str] = Field(default_factory=list, description="Data sources used")
    references: List[str] = Field(default_factory=list, description="External references")
    
    @validator("order")
    def validate_order(cls, v):
        """Validate section order is positive."""
        if v <= 0:
            raise ValueError("Section order must be positive")
        return v


class SecurityReport(BaseModel):
    """Complete security report with metadata and content."""
    
    # Report metadata
    report_id: str = Field(..., description="Unique report identifier")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    report_type: ReportType = Field(..., description="Type of report")
    format: ReportFormat = Field(..., description="Output format")
    
    # Classification and access control
    classification: ReportClassification = Field(..., description="Security classification")
    distribution_list: List[str] = Field(default_factory=list, description="Authorized recipients")
    access_restrictions: List[str] = Field(default_factory=list, description="Access restrictions")
    
    # Report content
    title: str = Field(..., description="Report title")
    executive_summary: str = Field(..., description="Executive summary")
    sections: List[ReportSection] = Field(default_factory=list, description="Report sections")
    
    # Source information
    source_events: List[str] = Field(default_factory=list, description="Source event IDs")
    related_reports: List[str] = Field(default_factory=list, description="Related report IDs")
    data_sources: List[str] = Field(default_factory=list, description="Data sources used")
    
    # Compliance and regulatory
    compliance_frameworks: List[ComplianceFramework] = Field(default_factory=list)
    regulatory_requirements: List[str] = Field(default_factory=list)
    retention_period_days: int = Field(default=2555, description="Retention period (7 years default)")
    
    # Quality and validation
    confidence_score: float = Field(..., description="Report confidence (0-1)")
    completeness_score: float = Field(..., description="Report completeness (0-1)")
    validation_status: str = Field(default="PENDING", description="Validation status")
    
    # Generation metadata
    generated_by: str = Field(..., description="System/user that generated report")
    generation_time_ms: float = Field(..., description="Generation time in milliseconds")
    template_version: str = Field(..., description="Template version used")
    
    # Multi-tenancy
    tenant_id: str = Field(..., description="Tenant identifier")
    
    @validator("confidence_score", "completeness_score")
    def validate_scores(cls, v):
        """Validate score ranges."""
        if not 0 <= v <= 1:
            raise ValueError("Scores must be between 0 and 1")
        return v


class ReportGenerator:
    """
    Production-grade security report generator for iSECTECH.
    
    Provides automated generation of security reports with customizable templates,
    multi-format output, and compliance-ready documentation capabilities.
    """
    
    def __init__(self, settings: Optional[Any] = None):
        """Initialize the report generator."""
        self.settings = settings or get_settings()
        self.audit_logger = AuditLogger(self.settings.security)
        
        # Template engine setup
        self.template_env = jinja2.Environment(
            loader=jinja2.DictLoader({}),  # Will be populated with templates
            autoescape=jinja2.select_autoescape(['html', 'xml']),
            trim_blocks=True,
            lstrip_blocks=True,
        )
        
        # Report templates and configurations
        self._report_templates = self._load_report_templates()
        self._section_templates = self._load_section_templates()
        self._compliance_mappings = self._load_compliance_mappings()
        self._format_configurations = self._load_format_configurations()
        
        # Style and branding configurations
        self._branding_configs = self._load_branding_configurations()
        self._style_sheets = self._load_style_sheets()
        
        # Performance tracking
        self._generation_metrics = {
            "total_reports_generated": 0,
            "average_generation_time": 0.0,
            "format_distribution": {},
            "type_distribution": {},
            "error_count": 0,
        }
        
        # Initialize template engine
        self._initialize_template_engine()
        
        logger.info("Report generator initialized successfully")
    
    def _load_report_templates(self) -> Dict[ReportType, Dict[str, Any]]:
        """Load report templates for different report types."""
        return {
            ReportType.INCIDENT_REPORT: {
                "title_template": "Security Incident Report - {event_id}",
                "required_sections": [
                    "executive_summary",
                    "incident_overview", 
                    "timeline_analysis",
                    "technical_details",
                    "impact_assessment",
                    "response_actions",
                    "lessons_learned",
                    "recommendations",
                ],
                "optional_sections": [
                    "threat_intelligence",
                    "compliance_impact",
                    "appendices",
                ],
                "default_classification": ReportClassification.CONFIDENTIAL,
                "estimated_pages": 15,
            },
            ReportType.EXECUTIVE_SUMMARY: {
                "title_template": "Executive Security Brief - {date}",
                "required_sections": [
                    "executive_summary",
                    "key_findings",
                    "business_impact",
                    "recommendations",
                    "next_steps",
                ],
                "optional_sections": [
                    "resource_requirements",
                    "timeline",
                ],
                "default_classification": ReportClassification.CONFIDENTIAL,
                "estimated_pages": 3,
            },
            ReportType.TECHNICAL_ANALYSIS: {
                "title_template": "Technical Security Analysis - {event_id}",
                "required_sections": [
                    "technical_summary",
                    "threat_analysis",
                    "indicators_analysis",
                    "attack_methodology",
                    "evidence_analysis",
                    "technical_recommendations",
                ],
                "optional_sections": [
                    "malware_analysis",
                    "network_analysis",
                    "forensic_artifacts",
                ],
                "default_classification": ReportClassification.CONFIDENTIAL,
                "estimated_pages": 25,
            },
            ReportType.COMPLIANCE_REPORT: {
                "title_template": "Compliance Assessment Report - {framework}",
                "required_sections": [
                    "compliance_summary",
                    "regulatory_requirements",
                    "gap_analysis",
                    "remediation_plan",
                    "certification_status",
                ],
                "optional_sections": [
                    "audit_findings",
                    "control_effectiveness",
                    "risk_assessment",
                ],
                "default_classification": ReportClassification.CONFIDENTIAL,
                "estimated_pages": 20,
            },
            ReportType.THREAT_INTELLIGENCE: {
                "title_template": "Threat Intelligence Report - {threat_category}",
                "required_sections": [
                    "threat_overview",
                    "actor_analysis",
                    "tactics_techniques_procedures",
                    "indicators_of_compromise",
                    "attribution_assessment",
                    "defensive_recommendations",
                ],
                "optional_sections": [
                    "campaign_analysis",
                    "infrastructure_analysis",
                    "victimology",
                ],
                "default_classification": ReportClassification.SECRET,
                "estimated_pages": 18,
            },
        }
    
    def _load_section_templates(self) -> Dict[str, str]:
        """Load section templates for report generation."""
        return {
            "executive_summary": """
## Executive Summary

**Incident Classification:** {{ threat_category }}
**Severity Level:** {{ threat_severity }}
**Detection Time:** {{ detection_time }}
**Impact Level:** {{ impact_level }}

### Key Findings
{{ key_findings }}

### Business Impact
{{ business_impact }}

### Immediate Actions Taken
{{ immediate_actions }}

### Recommendations
{{ recommendations }}
            """,
            
            "incident_overview": """
## Incident Overview

**Event ID:** {{ event_id }}
**Initial Detection:** {{ detection_time }}
**Source System:** {{ source_system }}
**Event Type:** {{ event_type }}
**Classification:** {{ classification }}

### Incident Description
{{ incident_description }}

### Affected Systems
{% for system in affected_systems %}
- {{ system }}
{% endfor %}

### Timeline Summary
{{ timeline_summary }}
            """,
            
            "technical_details": """
## Technical Analysis

### Threat Classification
- **Category:** {{ threat_category }}
- **Severity:** {{ threat_severity }}
- **Confidence:** {{ confidence_score }}%

### Technical Indicators
{% for indicator in technical_indicators %}
- **{{ indicator.type }}:** {{ indicator.value }}
  - Description: {{ indicator.description }}
  - Confidence: {{ indicator.confidence }}
{% endfor %}

### MITRE ATT&CK Mapping
{% if mitre_tactics %}
**Tactics:**
{% for tactic in mitre_tactics %}
- {{ tactic }}
{% endfor %}
{% endif %}

{% if mitre_techniques %}
**Techniques:**
{% for technique in mitre_techniques %}
- {{ technique }}
{% endfor %}
{% endif %}

### Evidence Summary
{{ evidence_summary }}
            """,
            
            "impact_assessment": """
## Impact Assessment

### Scope of Impact
{{ impact_scope }}

### Affected Assets
{% for asset in affected_assets %}
- **{{ asset.name }}:** {{ asset.impact_level }}
  - Description: {{ asset.description }}
  - Criticality: {{ asset.criticality }}
{% endfor %}

### Data Impact
{{ data_impact }}

### Business Process Impact
{{ business_process_impact }}

### Financial Impact Estimate
{{ financial_impact }}

### Regulatory Implications
{{ regulatory_implications }}
            """,
            
            "recommendations": """
## Recommendations

### Immediate Actions (0-24 hours)
{% for action in immediate_actions %}
- {{ action }}
{% endfor %}

### Short-term Improvements (1-4 weeks)
{% for improvement in short_term_improvements %}
- {{ improvement }}
{% endfor %}

### Long-term Strategic Changes (1-6 months)
{% for change in long_term_changes %}
- {{ change }}
{% endfor %}

### Resource Requirements
{{ resource_requirements }}

### Success Metrics
{% for metric in success_metrics %}
- {{ metric }}
{% endfor %}
            """,
        }
    
    def _load_compliance_mappings(self) -> Dict[ComplianceFramework, Dict[str, Any]]:
        """Load compliance framework mappings and requirements."""
        return {
            ComplianceFramework.GDPR: {
                "notification_timeline": "72 hours to supervisory authority",
                "required_sections": [
                    "personal_data_impact",
                    "notification_timeline",
                    "remediation_measures",
                    "contact_information",
                ],
                "reporting_authority": "Data Protection Authority",
                "retention_requirements": "As long as processing is lawful",
                "individual_notification": "Without undue delay if high risk",
            },
            ComplianceFramework.HIPAA: {
                "notification_timeline": "60 days to HHS and individuals",
                "required_sections": [
                    "phi_impact_assessment",
                    "risk_assessment",
                    "mitigation_actions",
                    "business_associate_notification",
                ],
                "reporting_authority": "HHS Office for Civil Rights",
                "retention_requirements": "6 years minimum",
                "individual_notification": "60 days maximum",
            },
            ComplianceFramework.PCI_DSS: {
                "notification_timeline": "Immediately to card brands",
                "required_sections": [
                    "cardholder_data_impact",
                    "forensic_investigation",
                    "remediation_plan",
                    "compliance_validation",
                ],
                "reporting_authority": "Card brands and acquiring bank",
                "retention_requirements": "1 year minimum",
                "individual_notification": "As required by state law",
            },
            ComplianceFramework.NIST: {
                "framework_functions": ["Identify", "Protect", "Detect", "Respond", "Recover"],
                "required_sections": [
                    "framework_alignment",
                    "control_effectiveness",
                    "improvement_opportunities",
                    "maturity_assessment",
                ],
                "assessment_scope": "Cybersecurity posture",
                "reporting_frequency": "Annual or as needed",
            },
        }
    
    def _load_format_configurations(self) -> Dict[ReportFormat, Dict[str, Any]]:
        """Load format-specific configurations."""
        return {
            ReportFormat.PDF: {
                "engine": "weasyprint",
                "styling": "css",
                "pagination": True,
                "vector_graphics": True,
                "encryption_support": True,
                "default_margins": "1in",
            },
            ReportFormat.HTML: {
                "responsive": True,
                "interactive_elements": True,
                "css_framework": "bootstrap",
                "javascript_enabled": True,
                "print_optimized": True,
            },
            ReportFormat.MARKDOWN: {
                "flavor": "github",
                "table_support": True,
                "code_highlighting": True,
                "math_rendering": False,
                "export_formats": ["html", "pdf"],
            },
            ReportFormat.JSON: {
                "schema_version": "1.0",
                "pretty_print": True,
                "include_metadata": True,
                "validation": True,
            },
            ReportFormat.DOCX: {
                "template_support": True,
                "custom_styles": True,
                "table_formatting": True,
                "header_footer": True,
                "track_changes": False,
            },
        }
    
    def _load_branding_configurations(self) -> Dict[str, Dict[str, Any]]:
        """Load branding configurations for different tenants."""
        return {
            "default": {
                "company_name": "iSECTECH Protect",
                "logo_url": "/assets/isectech-logo.png",
                "primary_color": "#1e3a8a",
                "secondary_color": "#64748b", 
                "accent_color": "#ef4444",
                "font_family": "Inter, system-ui, sans-serif",
                "header_style": "professional",
                "footer_template": "Confidential - iSECTECH Protect Security Report",
            },
            "white_label": {
                "company_name": "{{ tenant.company_name }}",
                "logo_url": "{{ tenant.logo_url }}",
                "primary_color": "{{ tenant.primary_color }}",
                "secondary_color": "{{ tenant.secondary_color }}",
                "accent_color": "{{ tenant.accent_color }}",
                "font_family": "{{ tenant.font_family }}",
                "header_style": "{{ tenant.header_style }}",
                "footer_template": "{{ tenant.footer_template }}",
            },
        }
    
    def _load_style_sheets(self) -> Dict[str, str]:
        """Load CSS style sheets for different report formats."""
        return {
            "professional": """
                body { 
                    font-family: 'Inter', system-ui, sans-serif; 
                    line-height: 1.6; 
                    color: #374151; 
                    max-width: 8.5in;
                    margin: 0 auto;
                    padding: 1in;
                }
                h1 { 
                    color: #1e3a8a; 
                    border-bottom: 3px solid #1e3a8a; 
                    padding-bottom: 0.5rem;
                    font-size: 2rem;
                    font-weight: 700;
                }
                h2 { 
                    color: #1e40af; 
                    margin-top: 2rem;
                    font-size: 1.5rem;
                    font-weight: 600;
                }
                h3 { 
                    color: #1e40af; 
                    margin-top: 1.5rem;
                    font-size: 1.25rem;
                    font-weight: 600;
                }
                .classification {
                    background: #ef4444;
                    color: white;
                    padding: 0.5rem 1rem;
                    font-weight: bold;
                    text-align: center;
                    margin-bottom: 1rem;
                }
                .executive-summary {
                    background: #f8fafc;
                    border-left: 4px solid #1e3a8a;
                    padding: 1rem;
                    margin: 1rem 0;
                }
                .threat-indicator {
                    background: #fef2f2;
                    border: 1px solid #fecaca;
                    padding: 0.75rem;
                    margin: 0.5rem 0;
                    border-radius: 0.375rem;
                }
                table {
                    width: 100%;
                    border-collapse: collapse;
                    margin: 1rem 0;
                }
                th, td {
                    border: 1px solid #d1d5db;
                    padding: 0.75rem;
                    text-align: left;
                }
                th {
                    background: #f9fafb;
                    font-weight: 600;
                }
                .footer {
                    margin-top: 2rem;
                    padding-top: 1rem;
                    border-top: 1px solid #d1d5db;
                    font-size: 0.875rem;
                    color: #6b7280;
                    text-align: center;
                }
            """,
            
            "technical": """
                body { 
                    font-family: 'Fira Code', 'Courier New', monospace; 
                    line-height: 1.5; 
                    color: #1f2937; 
                    background: #ffffff;
                }
                .code-block {
                    background: #1f2937;
                    color: #f9fafb;
                    padding: 1rem;
                    border-radius: 0.5rem;
                    font-family: 'Fira Code', monospace;
                    overflow-x: auto;
                }
                .technical-detail {
                    background: #f3f4f6;
                    border: 1px solid #d1d5db;
                    padding: 1rem;
                    margin: 1rem 0;
                    border-radius: 0.375rem;
                }
                .ioc-indicator {
                    background: #fffbeb;
                    border: 1px solid #fbbf24;
                    padding: 0.5rem;
                    margin: 0.25rem 0;
                    border-radius: 0.25rem;
                    font-family: monospace;
                }
            """,
        }
    
    def _initialize_template_engine(self) -> None:
        """Initialize the Jinja2 template engine with custom filters."""
        # Add custom filters
        self.template_env.filters['format_timestamp'] = self._format_timestamp
        self.template_env.filters['format_severity'] = self._format_severity
        self.template_env.filters['format_classification'] = self._format_classification
        self.template_env.filters['truncate_ioc'] = self._truncate_ioc
        
        # Add section templates to loader
        template_dict = {}
        for section_name, template_content in self._section_templates.items():
            template_dict[f"{section_name}.j2"] = template_content
        
        self.template_env.loader = jinja2.DictLoader(template_dict)
    
    def _format_timestamp(self, timestamp: datetime) -> str:
        """Format timestamp for reports."""
        return timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")
    
    def _format_severity(self, severity: ThreatSeverity) -> str:
        """Format severity level with styling."""
        severity_styles = {
            ThreatSeverity.CRITICAL: "🔴 CRITICAL",
            ThreatSeverity.HIGH: "🟠 HIGH",
            ThreatSeverity.MEDIUM: "🟡 MEDIUM",
            ThreatSeverity.LOW: "🟢 LOW",
            ThreatSeverity.INFORMATIONAL: "🔵 INFORMATIONAL",
        }
        return severity_styles.get(severity, str(severity))
    
    def _format_classification(self, classification: ReportClassification) -> str:
        """Format security classification with appropriate styling."""
        return f"**{classification.value}**"
    
    def _truncate_ioc(self, ioc: str, max_length: int = 50) -> str:
        """Truncate IOC for display."""
        if len(ioc) <= max_length:
            return ioc
        return f"{ioc[:max_length-3]}..."
    
    async def generate_report(
        self,
        report_type: ReportType,
        context: SecurityContext,
        threat_explanation: Optional[ThreatExplanation] = None,
        investigation_recommendation: Optional[InvestigationRecommendation] = None,
        additional_data: Optional[Dict[str, Any]] = None,
        output_format: ReportFormat = ReportFormat.HTML,
        custom_template: Optional[str] = None,
        compliance_frameworks: Optional[List[ComplianceFramework]] = None,
    ) -> SecurityReport:
        """
        Generate a comprehensive security report.
        
        Args:
            report_type: Type of report to generate
            context: Security context with event details
            threat_explanation: Optional threat explanation data
            investigation_recommendation: Optional investigation recommendations
            additional_data: Optional additional data for report
            output_format: Desired output format
            custom_template: Optional custom template override
            compliance_frameworks: Optional compliance frameworks to include
            
        Returns:
            Complete security report with metadata and content
        """
        start_time = datetime.utcnow()
        report_id = f"report-{report_type.value.lower()}-{context.event_id}-{int(start_time.timestamp())}"
        
        try:
            logger.info(f"Generating {report_type.value} report for event {context.event_id}")
            
            # Audit log the report generation request
            await self.audit_logger.log_security_event(
                event_type="REPORT_GENERATION_STARTED",
                details={
                    "event_id": context.event_id,
                    "report_id": report_id,
                    "report_type": report_type.value,
                    "output_format": output_format.value,
                    "tenant_id": context.tenant_id,
                },
                classification=context.classification,
                tenant_id=context.tenant_id,
            )
            
            # Prepare report data
            report_data = await self._prepare_report_data(
                context, threat_explanation, investigation_recommendation, additional_data
            )
            
            # Generate report title
            title = await self._generate_report_title(report_type, context, report_data)
            
            # Generate executive summary
            executive_summary = await self._generate_executive_summary(
                report_type, context, threat_explanation, report_data
            )
            
            # Build report sections
            sections = await self._build_report_sections(
                report_type, context, report_data, custom_template
            )
            
            # Determine classification and compliance requirements
            classification = self._determine_report_classification(context, report_type)
            frameworks = compliance_frameworks or self._determine_compliance_frameworks(context)
            
            # Calculate quality scores
            confidence_score = self._calculate_confidence_score(
                context, threat_explanation, investigation_recommendation
            )
            completeness_score = self._calculate_completeness_score(sections, report_type)
            
            # Calculate generation time
            end_time = datetime.utcnow()
            generation_time_ms = (end_time - start_time).total_seconds() * 1000
            
            # Create report
            report = SecurityReport(
                report_id=report_id,
                report_type=report_type,
                format=output_format,
                classification=classification,
                title=title,
                executive_summary=executive_summary,
                sections=sections,
                source_events=[context.event_id],
                compliance_frameworks=frameworks,
                confidence_score=confidence_score,
                completeness_score=completeness_score,
                generated_by="iSECTECH NLP Security Assistant",
                generation_time_ms=generation_time_ms,
                template_version="1.0.0",
                tenant_id=context.tenant_id,
            )
            
            # Apply post-processing
            await self._apply_post_processing(report, output_format)
            
            # Update metrics
            self._update_generation_metrics(report_type, output_format, start_time)
            
            # Audit log successful generation
            await self.audit_logger.log_security_event(
                event_type="REPORT_GENERATION_COMPLETED",
                details={
                    "report_id": report_id,
                    "sections_count": len(sections),
                    "confidence_score": confidence_score,
                    "completeness_score": completeness_score,
                    "generation_time_ms": generation_time_ms,
                },
                classification=context.classification,
                tenant_id=context.tenant_id,
            )
            
            logger.info(f"Generated report {report_id} in {generation_time_ms:.2f}ms")
            return report
            
        except Exception as e:
            logger.error(f"Failed to generate report: {e}")
            await self.audit_logger.log_security_event(
                event_type="REPORT_GENERATION_FAILED",
                details={
                    "report_id": report_id,
                    "error": str(e),
                },
                severity="HIGH",
                classification=context.classification,
                tenant_id=context.tenant_id,
            )
            self._generation_metrics["error_count"] += 1
            raise
    
    async def _prepare_report_data(
        self,
        context: SecurityContext,
        threat_explanation: Optional[ThreatExplanation],
        investigation_recommendation: Optional[InvestigationRecommendation],
        additional_data: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Prepare consolidated data for report generation."""
        data = {
            # Context data
            "event_id": context.event_id,
            "timestamp": context.timestamp,
            "source_system": context.source_system,
            "event_type": context.event_type,
            "classification": context.classification,
            "tenant_id": context.tenant_id,
            
            # Event details
            "raw_message": context.raw_message,
            "structured_data": context.structured_data,
            "threat_indicators": context.threat_indicators,
            "mitre_tactics": context.mitre_tactics,
            "mitre_techniques": context.mitre_techniques,
            
            # Context enrichment
            "asset_info": context.asset_info or {},
            "user_context": context.user_context or {},
            "network_context": context.network_context or {},
        }
        
        # Add threat explanation data
        if threat_explanation:
            data.update({
                "threat_category": getattr(threat_explanation, 'threat_category', 'Unknown'),
                "threat_severity": getattr(threat_explanation, 'threat_severity', 'Unknown'),
                "threat_title": threat_explanation.title,
                "threat_summary": threat_explanation.summary,
                "detailed_explanation": threat_explanation.detailed_explanation,
                "impact_analysis": threat_explanation.impact_analysis,
                "business_context": threat_explanation.business_context,
                "risk_factors": threat_explanation.risk_factors,
                "technical_details": threat_explanation.technical_details,
                "indicators_explained": threat_explanation.indicators_explained,
                "mitre_context": threat_explanation.mitre_context,
                "immediate_actions": threat_explanation.immediate_actions,
                "prevention_measures": threat_explanation.prevention_measures,
            })
        
        # Add investigation recommendation data
        if investigation_recommendation:
            data.update({
                "investigation_title": investigation_recommendation.investigation_title,
                "investigation_summary": investigation_recommendation.executive_summary,
                "investigation_complexity": investigation_recommendation.complexity,
                "investigation_priority": investigation_recommendation.priority,
                "estimated_hours": investigation_recommendation.estimated_total_hours,
                "required_expertise": investigation_recommendation.required_expertise,
                "investigation_steps": investigation_recommendation.investigation_steps,
                "evidence_targets": investigation_recommendation.key_evidence_targets,
                "escalation_triggers": investigation_recommendation.escalation_triggers,
            })
        
        # Add additional data
        if additional_data:
            data.update(additional_data)
        
        return data
    
    async def _generate_report_title(
        self,
        report_type: ReportType,
        context: SecurityContext,
        report_data: Dict[str, Any],
    ) -> str:
        """Generate report title based on type and context."""
        template_config = self._report_templates.get(report_type, {})
        title_template = template_config.get("title_template", f"{report_type.value} - {{event_id}}")
        
        # Prepare template variables
        template_vars = {
            "event_id": context.event_id,
            "date": datetime.utcnow().strftime("%Y-%m-%d"),
            "threat_category": report_data.get("threat_category", "Security Event"),
            "framework": report_data.get("compliance_framework", "Multiple"),
        }
        
        return title_template.format(**template_vars)
    
    async def _generate_executive_summary(
        self,
        report_type: ReportType,
        context: SecurityContext,
        threat_explanation: Optional[ThreatExplanation],
        report_data: Dict[str, Any],
    ) -> str:
        """Generate executive summary for the report."""
        try:
            if threat_explanation and threat_explanation.style == ExplanationStyle.EXECUTIVE:
                return threat_explanation.summary
            
            # Generate summary based on report type
            if report_type == ReportType.EXECUTIVE_SUMMARY:
                return await self._generate_executive_brief(context, report_data)
            elif report_type == ReportType.INCIDENT_REPORT:
                return await self._generate_incident_summary(context, report_data)
            elif report_type == ReportType.COMPLIANCE_REPORT:
                return await self._generate_compliance_summary(context, report_data)
            else:
                return await self._generate_generic_summary(context, report_data)
        
        except Exception as e:
            logger.warning(f"Executive summary generation failed: {e}")
            return f"Executive summary for {report_type.value} - Event {context.event_id}. Detailed analysis and recommendations provided in the following sections."
    
    async def _generate_executive_brief(
        self, 
        context: SecurityContext, 
        report_data: Dict[str, Any]
    ) -> str:
        """Generate executive brief summary."""
        threat_category = report_data.get("threat_category", "security event")
        threat_severity = report_data.get("threat_severity", "unknown severity")
        
        return f"""
**Security Event Summary**

A {threat_category} of {threat_severity} has been detected and is currently under investigation. This executive brief provides a high-level overview of the situation, immediate actions taken, and recommended next steps.

**Key Points:**
- Event detected on {context.timestamp.strftime('%Y-%m-%d at %H:%M UTC')}
- Source system: {context.source_system}
- Classification level: {context.classification.value}
- Immediate response initiated

**Business Impact:** {report_data.get('business_context', 'Impact assessment in progress')}

**Status:** Investigation and response procedures are actively underway according to established protocols.
        """.strip()
    
    async def _generate_incident_summary(
        self, 
        context: SecurityContext, 
        report_data: Dict[str, Any]
    ) -> str:
        """Generate incident report summary."""
        return f"""
**Incident Report Summary**

This report provides a comprehensive analysis of security incident {context.event_id} detected on {context.timestamp.strftime('%Y-%m-%d at %H:%M UTC')}.

**Incident Classification:** {report_data.get('threat_category', 'Under Investigation')}
**Severity Level:** {report_data.get('threat_severity', 'Assessment in Progress')}
**Affected Systems:** {context.source_system}

**Investigation Status:** {'Complete' if report_data.get('investigation_complete') else 'In Progress'}

This document contains detailed analysis, timeline reconstruction, impact assessment, and recommendations for preventing similar incidents.
        """.strip()
    
    async def _generate_compliance_summary(
        self, 
        context: SecurityContext, 
        report_data: Dict[str, Any]
    ) -> str:
        """Generate compliance report summary."""
        frameworks = report_data.get('compliance_frameworks', ['General Security'])
        
        return f"""
**Compliance Assessment Summary**

This report evaluates the organization's compliance posture in relation to security incident {context.event_id} and applicable regulatory frameworks.

**Applicable Frameworks:** {', '.join(str(f) for f in frameworks)}
**Assessment Date:** {datetime.utcnow().strftime('%Y-%m-%d')}
**Classification:** {context.classification.value}

**Compliance Status:** Assessment complete with recommendations for maintaining regulatory compliance and improving security posture.
        """.strip()
    
    async def _generate_generic_summary(
        self, 
        context: SecurityContext, 
        report_data: Dict[str, Any]
    ) -> str:
        """Generate generic summary for other report types."""
        return f"""
**Security Analysis Summary**

This report provides detailed analysis of security event {context.event_id} detected on {context.timestamp.strftime('%Y-%m-%d at %H:%M UTC')}.

**Event Details:**
- Source: {context.source_system}
- Type: {context.event_type}
- Classification: {context.classification.value}

**Analysis Status:** Comprehensive analysis complete with findings and recommendations detailed in the following sections.
        """.strip()
    
    async def _build_report_sections(
        self,
        report_type: ReportType,
        context: SecurityContext,
        report_data: Dict[str, Any],
        custom_template: Optional[str] = None,
    ) -> List[ReportSection]:
        """Build report sections based on type and available data."""
        sections = []
        
        try:
            template_config = self._report_templates.get(report_type, {})
            required_sections = template_config.get("required_sections", [])
            optional_sections = template_config.get("optional_sections", [])
            
            section_order = 1
            
            # Build required sections
            for section_name in required_sections:
                section = await self._build_section(
                    section_name, section_order, context, report_data, required=True
                )
                if section:
                    sections.append(section)
                    section_order += 1
            
            # Build optional sections if data is available
            for section_name in optional_sections:
                if self._should_include_optional_section(section_name, report_data):
                    section = await self._build_section(
                        section_name, section_order, context, report_data, required=False
                    )
                    if section:
                        sections.append(section)
                        section_order += 1
            
            return sections
        
        except Exception as e:
            logger.warning(f"Section building failed: {e}")
            # Return basic section as fallback
            return [
                ReportSection(
                    section_id="basic_analysis",
                    title="Security Analysis",
                    content=f"Analysis of security event {context.event_id}. Please refer to detailed investigation results.",
                    order=1,
                )
            ]
    
    async def _build_section(
        self,
        section_name: str,
        order: int,
        context: SecurityContext,
        report_data: Dict[str, Any],
        required: bool = True,
    ) -> Optional[ReportSection]:
        """Build an individual report section."""
        try:
            # Get section template
            template_content = self._section_templates.get(section_name)
            if not template_content:
                logger.warning(f"No template found for section: {section_name}")
                return None
            
            # Render section content
            template = self.template_env.from_string(template_content)
            content = template.render(**report_data)
            
            # Determine section title
            title = self._get_section_title(section_name)
            
            # Determine classification
            classification = self._determine_section_classification(section_name, context)
            
            return ReportSection(
                section_id=section_name,
                title=title,
                content=content,
                order=order,
                required=required,
                classification=classification,
                data_sources=[context.source_system],
            )
        
        except Exception as e:
            logger.warning(f"Failed to build section {section_name}: {e}")
            return None
    
    def _get_section_title(self, section_name: str) -> str:
        """Get human-readable title for section."""
        title_mapping = {
            "executive_summary": "Executive Summary",
            "incident_overview": "Incident Overview",
            "timeline_analysis": "Timeline Analysis",
            "technical_details": "Technical Analysis",
            "impact_assessment": "Impact Assessment",
            "response_actions": "Response Actions",
            "lessons_learned": "Lessons Learned",
            "recommendations": "Recommendations",
            "threat_intelligence": "Threat Intelligence",
            "compliance_impact": "Compliance Impact",
            "appendices": "Appendices",
        }
        
        return title_mapping.get(section_name, section_name.replace("_", " ").title())
    
    def _should_include_optional_section(
        self, 
        section_name: str, 
        report_data: Dict[str, Any]
    ) -> bool:
        """Determine if optional section should be included."""
        inclusion_criteria = {
            "threat_intelligence": bool(report_data.get("threat_indicators")),
            "compliance_impact": bool(report_data.get("compliance_frameworks")),
            "malware_analysis": "malware" in str(report_data.get("threat_category", "")).lower(),
            "network_analysis": bool(report_data.get("network_context")),
            "forensic_artifacts": bool(report_data.get("evidence_targets")),
        }
        
        return inclusion_criteria.get(section_name, True)
    
    def _determine_report_classification(
        self, 
        context: SecurityContext, 
        report_type: ReportType
    ) -> ReportClassification:
        """Determine appropriate classification for the report."""
        # Start with context classification
        context_mapping = {
            SecurityClassification.UNCLASSIFIED: ReportClassification.UNCLASSIFIED,
            SecurityClassification.CONFIDENTIAL: ReportClassification.CONFIDENTIAL,
            SecurityClassification.SECRET: ReportClassification.SECRET,
            SecurityClassification.TOP_SECRET: ReportClassification.TOP_SECRET,
        }
        
        base_classification = context_mapping.get(
            context.classification, 
            ReportClassification.CONFIDENTIAL
        )
        
        # Adjust based on report type
        template_config = self._report_templates.get(report_type, {})
        default_classification = template_config.get(
            "default_classification", 
            ReportClassification.CONFIDENTIAL
        )
        
        # Return higher of the two classifications
        classifications = [ReportClassification.UNCLASSIFIED, ReportClassification.CONFIDENTIAL, 
                         ReportClassification.SECRET, ReportClassification.TOP_SECRET]
        
        base_index = classifications.index(base_classification)
        default_index = classifications.index(default_classification)
        
        return classifications[max(base_index, default_index)]
    
    def _determine_section_classification(
        self, 
        section_name: str, 
        context: SecurityContext
    ) -> ReportClassification:
        """Determine classification for individual sections."""
        # High-sensitivity sections
        sensitive_sections = {
            "technical_details", 
            "threat_intelligence", 
            "forensic_artifacts",
            "malware_analysis",
        }
        
        if section_name in sensitive_sections:
            return ReportClassification.CONFIDENTIAL
        else:
            return ReportClassification.UNCLASSIFIED
    
    def _determine_compliance_frameworks(
        self, 
        context: SecurityContext
    ) -> List[ComplianceFramework]:
        """Determine applicable compliance frameworks."""
        frameworks = []
        
        # Determine based on classification and context
        if context.classification in [SecurityClassification.SECRET, SecurityClassification.TOP_SECRET]:
            frameworks.append(ComplianceFramework.FISMA)
        
        # Add other frameworks based on context clues
        if "healthcare" in str(context.structured_data).lower():
            frameworks.append(ComplianceFramework.HIPAA)
        
        if "payment" in str(context.structured_data).lower() or "card" in str(context.structured_data).lower():
            frameworks.append(ComplianceFramework.PCI_DSS)
        
        # Default to NIST framework
        if not frameworks:
            frameworks.append(ComplianceFramework.NIST)
        
        return frameworks
    
    def _calculate_confidence_score(
        self,
        context: SecurityContext,
        threat_explanation: Optional[ThreatExplanation],
        investigation_recommendation: Optional[InvestigationRecommendation],
    ) -> float:
        """Calculate overall confidence score for the report."""
        scores = []
        
        # Base score from context completeness
        context_score = 0.7
        if context.threat_indicators:
            context_score += 0.1
        if context.mitre_tactics:
            context_score += 0.1
        scores.append(context_score)
        
        # Add threat explanation confidence
        if threat_explanation:
            scores.append(threat_explanation.confidence_score)
        
        # Add investigation recommendation confidence
        if investigation_recommendation:
            scores.append(investigation_recommendation.confidence_score)
        
        return sum(scores) / len(scores) if scores else 0.7
    
    def _calculate_completeness_score(
        self, 
        sections: List[ReportSection], 
        report_type: ReportType
    ) -> float:
        """Calculate completeness score based on sections."""
        template_config = self._report_templates.get(report_type, {})
        required_sections = template_config.get("required_sections", [])
        
        if not required_sections:
            return 0.8  # Default completeness
        
        section_names = {section.section_id for section in sections}
        completed_required = len(section_names.intersection(required_sections))
        
        return completed_required / len(required_sections)
    
    async def _apply_post_processing(
        self, 
        report: SecurityReport, 
        output_format: ReportFormat
    ) -> None:
        """Apply format-specific post-processing."""
        try:
            if output_format == ReportFormat.HTML:
                await self._apply_html_processing(report)
            elif output_format == ReportFormat.PDF:
                await self._apply_pdf_processing(report)
            elif output_format == ReportFormat.MARKDOWN:
                await self._apply_markdown_processing(report)
            # Add other format processors as needed
        
        except Exception as e:
            logger.warning(f"Post-processing failed for {output_format}: {e}")
    
    async def _apply_html_processing(self, report: SecurityReport) -> None:
        """Apply HTML-specific processing."""
        # Add CSS styling and interactive elements
        for section in report.sections:
            if section.content_type == "text":
                # Add HTML formatting
                section.content = section.content.replace("\n\n", "</p><p>")
                section.content = f"<p>{section.content}</p>"
    
    async def _apply_pdf_processing(self, report: SecurityReport) -> None:
        """Apply PDF-specific processing."""
        # Add page breaks and PDF-specific formatting
        for section in report.sections:
            if section.order > 1:
                section.content = f'<div style="page-break-before: always;"></div>{section.content}'
    
    async def _apply_markdown_processing(self, report: SecurityReport) -> None:
        """Apply Markdown-specific processing."""
        # Ensure proper Markdown formatting
        for section in report.sections:
            # Ensure headers are properly formatted
            if not section.content.startswith("#"):
                section.content = f"## {section.title}\n\n{section.content}"
    
    def _update_generation_metrics(
        self,
        report_type: ReportType,
        output_format: ReportFormat,
        start_time: datetime,
    ) -> None:
        """Update report generation metrics."""
        self._generation_metrics["total_reports_generated"] += 1
        
        # Update format distribution
        format_key = output_format.value
        if format_key not in self._generation_metrics["format_distribution"]:
            self._generation_metrics["format_distribution"][format_key] = 0
        self._generation_metrics["format_distribution"][format_key] += 1
        
        # Update type distribution
        type_key = report_type.value
        if type_key not in self._generation_metrics["type_distribution"]:
            self._generation_metrics["type_distribution"][type_key] = 0
        self._generation_metrics["type_distribution"][type_key] += 1
        
        # Update average generation time
        generation_time = (datetime.utcnow() - start_time).total_seconds() * 1000
        current_avg = self._generation_metrics["average_generation_time"]
        count = self._generation_metrics["total_reports_generated"]
        
        self._generation_metrics["average_generation_time"] = (
            (current_avg * (count - 1)) + generation_time
        ) / count
    
    def get_generation_metrics(self) -> Dict[str, Any]:
        """Get report generation metrics."""
        return self._generation_metrics.copy()
    
    def get_supported_formats(self) -> List[ReportFormat]:
        """Get list of supported output formats."""
        return list(ReportFormat)
    
    def get_supported_types(self) -> List[ReportType]:
        """Get list of supported report types."""
        return list(ReportType)
    
    def get_template_info(self) -> Dict[str, Any]:
        """Get information about available templates."""
        return {
            "report_types": {
                rtype.value: {
                    "required_sections": config.get("required_sections", []),
                    "optional_sections": config.get("optional_sections", []),
                    "estimated_pages": config.get("estimated_pages", "Variable"),
                }
                for rtype, config in self._report_templates.items()
            },
            "section_templates": list(self._section_templates.keys()),
            "compliance_frameworks": [f.value for f in ComplianceFramework],
            "output_formats": [f.value for f in ReportFormat],
        }