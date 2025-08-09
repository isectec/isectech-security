"""
API Models for NLP Security Assistant Service

Defines request/response models for:
- Security event processing and threat analysis
- Plain English threat explanations for multiple audiences
- Guided investigation recommendations and workflows
- Automated report generation in multiple formats
- IOC extraction and MITRE ATT&CK mapping
"""

from datetime import datetime
from typing import Any, Dict, List, Optional, Union
from uuid import UUID

from pydantic import BaseModel, Field, validator


class SecurityEvent(BaseModel):
    """Security event for NLP processing"""
    event_id: str = Field(..., description="Unique event identifier")
    timestamp: datetime = Field(..., description="Event timestamp")
    event_type: str = Field(..., description="Type of security event")
    source_system: str = Field(..., description="Source system or sensor")
    severity: str = Field(..., description="Event severity level")
    raw_data: Dict[str, Any] = Field(..., description="Raw event data")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")
    
    @validator('severity')
    def validate_severity(cls, v):
        allowed_severities = ['low', 'medium', 'high', 'critical']
        if v.lower() not in allowed_severities:
            raise ValueError(f"Severity must be one of: {allowed_severities}")
        return v.lower()
    
    @validator('event_type')
    def validate_event_type(cls, v):
        allowed_types = [
            'malware_detection', 'intrusion_attempt', 'data_exfiltration',
            'privilege_escalation', 'lateral_movement', 'persistence',
            'command_and_control', 'reconnaissance', 'phishing',
            'anomalous_behavior', 'policy_violation', 'system_compromise'
        ]
        if v not in allowed_types:
            raise ValueError(f"Event type must be one of: {allowed_types}")
        return v


class ProcessEventRequest(BaseModel):
    """Request for processing security events"""
    events: List[SecurityEvent] = Field(..., description="Security events to process")
    tenant_id: str = Field(..., description="Tenant identifier")
    processing_options: Dict[str, Any] = Field(
        default_factory=dict,
        description="Processing configuration options"
    )
    extract_iocs: bool = Field(True, description="Extract indicators of compromise")
    classify_threats: bool = Field(True, description="Classify threat types")
    map_mitre: bool = Field(True, description="Map to MITRE ATT&CK framework")
    
    @validator('events')
    def validate_events_count(cls, v):
        if len(v) > 100:
            raise ValueError("Maximum 100 events per request")
        if len(v) == 0:
            raise ValueError("At least one event required")
        return v


class ThreatExplanationRequest(BaseModel):
    """Request for threat explanation generation"""
    event_id: str = Field(..., description="Event identifier")
    threat_data: Dict[str, Any] = Field(..., description="Threat analysis data")
    audience: str = Field(..., description="Target audience for explanation")
    include_technical_details: bool = Field(True, description="Include technical details")
    include_business_impact: bool = Field(True, description="Include business impact analysis")
    include_recommendations: bool = Field(True, description="Include recommendations")
    tenant_id: str = Field(..., description="Tenant identifier")
    
    @validator('audience')
    def validate_audience(cls, v):
        allowed_audiences = ['technical', 'executive', 'analyst', 'customer', 'compliance']
        if v.lower() not in allowed_audiences:
            raise ValueError(f"Audience must be one of: {allowed_audiences}")
        return v.lower()


class InvestigationRequest(BaseModel):
    """Request for investigation guidance"""
    incident_id: str = Field(..., description="Incident identifier")
    threat_type: str = Field(..., description="Type of threat")
    severity: str = Field(..., description="Incident severity")
    available_resources: List[str] = Field(..., description="Available investigation resources")
    time_constraints: Optional[str] = Field(None, description="Time constraints")
    compliance_requirements: List[str] = Field(
        default_factory=list,
        description="Applicable compliance requirements"
    )
    tenant_id: str = Field(..., description="Tenant identifier")
    context_data: Dict[str, Any] = Field(
        default_factory=dict,
        description="Additional context data"
    )


class ReportGenerationRequest(BaseModel):
    """Request for automated report generation"""
    report_type: str = Field(..., description="Type of report to generate")
    data_sources: List[Dict[str, Any]] = Field(..., description="Data sources for report")
    report_format: str = Field("pdf", description="Output format")
    include_executive_summary: bool = Field(True, description="Include executive summary")
    include_technical_details: bool = Field(True, description="Include technical details")
    include_recommendations: bool = Field(True, description="Include recommendations")
    tenant_id: str = Field(..., description="Tenant identifier")
    template_options: Dict[str, Any] = Field(
        default_factory=dict,
        description="Template customization options"
    )
    
    @validator('report_type')
    def validate_report_type(cls, v):
        allowed_types = ['incident', 'executive', 'technical', 'compliance', 'threat_intelligence']
        if v not in allowed_types:
            raise ValueError(f"Report type must be one of: {allowed_types}")
        return v
    
    @validator('report_format')
    def validate_report_format(cls, v):
        allowed_formats = ['pdf', 'html', 'markdown', 'json', 'docx', 'xml']
        if v not in allowed_formats:
            raise ValueError(f"Report format must be one of: {allowed_formats}")
        return v


class IOCInfo(BaseModel):
    """Indicator of Compromise information"""
    ioc_type: str = Field(..., description="Type of IOC")
    value: str = Field(..., description="IOC value")
    confidence: float = Field(..., description="Confidence score (0-1)")
    context: str = Field(..., description="Context where IOC was found")
    first_seen: datetime = Field(..., description="When IOC was first detected")
    threat_relevance: str = Field(..., description="Relevance to threat")


class ThreatClassification(BaseModel):
    """Threat classification result"""
    threat_type: str = Field(..., description="Classified threat type")
    confidence: float = Field(..., description="Classification confidence (0-1)")
    description: str = Field(..., description="Threat description")
    mitre_tactics: List[str] = Field(..., description="MITRE ATT&CK tactics")
    mitre_techniques: List[str] = Field(..., description="MITRE ATT&CK techniques")
    kill_chain_phase: str = Field(..., description="Cyber Kill Chain phase")


class ProcessedEvent(BaseModel):
    """Processed security event with NLP analysis"""
    event_id: str = Field(..., description="Event identifier")
    original_event: SecurityEvent = Field(..., description="Original event data")
    processing_timestamp: datetime = Field(..., description="Processing timestamp")
    extracted_iocs: List[IOCInfo] = Field(..., description="Extracted IOCs")
    threat_classification: ThreatClassification = Field(..., description="Threat classification")
    natural_language_summary: str = Field(..., description="Natural language summary")
    severity_assessment: str = Field(..., description="Assessed severity")
    recommended_actions: List[str] = Field(..., description="Recommended immediate actions")
    processing_metadata: Dict[str, Any] = Field(..., description="Processing metadata")


class ProcessEventResponse(BaseModel):
    """Response for event processing"""
    tenant_id: str = Field(..., description="Tenant identifier")
    processing_id: str = Field(..., description="Unique processing identifier")
    timestamp: datetime = Field(..., description="Processing timestamp")
    events_processed: int = Field(..., description="Number of events processed")
    processed_events: List[ProcessedEvent] = Field(..., description="Processed events")
    summary_statistics: Dict[str, Any] = Field(..., description="Processing statistics")
    processing_time_ms: float = Field(..., description="Processing time in milliseconds")


class ThreatExplanation(BaseModel):
    """Threat explanation for specific audience"""
    explanation_id: str = Field(..., description="Unique explanation identifier")
    event_id: str = Field(..., description="Related event identifier")
    audience: str = Field(..., description="Target audience")
    title: str = Field(..., description="Explanation title")
    executive_summary: str = Field(..., description="Executive summary")
    technical_explanation: Optional[str] = Field(None, description="Technical explanation")
    business_impact: str = Field(..., description="Business impact analysis")
    immediate_actions: List[str] = Field(..., description="Immediate action items")
    prevention_measures: List[str] = Field(..., description="Prevention measures")
    ioc_explanations: List[Dict[str, str]] = Field(..., description="IOC explanations")
    mitre_context: Dict[str, Any] = Field(..., description="MITRE ATT&CK context")
    quality_scores: Dict[str, float] = Field(..., description="Explanation quality scores")
    generated_at: datetime = Field(..., description="Generation timestamp")


class InvestigationWorkflow(BaseModel):
    """Investigation workflow step"""
    step_number: int = Field(..., description="Step number in workflow")
    title: str = Field(..., description="Step title")
    description: str = Field(..., description="Step description")
    estimated_time: str = Field(..., description="Estimated time to complete")
    required_skills: List[str] = Field(..., description="Required skills")
    tools_needed: List[str] = Field(..., description="Required tools")
    evidence_to_collect: List[str] = Field(..., description="Evidence to collect")
    success_criteria: List[str] = Field(..., description="Success criteria")
    dependencies: List[int] = Field(..., description="Dependent step numbers")


class InvestigationGuidance(BaseModel):
    """Investigation guidance and recommendations"""
    guidance_id: str = Field(..., description="Unique guidance identifier")
    incident_id: str = Field(..., description="Related incident identifier")
    threat_analysis: Dict[str, Any] = Field(..., description="Threat analysis summary")
    investigation_workflow: List[InvestigationWorkflow] = Field(..., description="Investigation steps")
    resource_requirements: Dict[str, Any] = Field(..., description="Resource requirements")
    estimated_timeline: str = Field(..., description="Estimated investigation timeline")
    risk_assessment: Dict[str, str] = Field(..., description="Risk assessment")
    escalation_triggers: List[str] = Field(..., description="Escalation triggers")
    compliance_considerations: List[str] = Field(..., description="Compliance considerations")
    stakeholder_communications: Dict[str, str] = Field(..., description="Stakeholder communication plan")
    success_metrics: List[str] = Field(..., description="Investigation success metrics")
    generated_at: datetime = Field(..., description="Generation timestamp")


class GeneratedReport(BaseModel):
    """Generated security report"""
    report_id: str = Field(..., description="Unique report identifier")
    report_type: str = Field(..., description="Type of report")
    report_format: str = Field(..., description="Report format")
    title: str = Field(..., description="Report title")
    executive_summary: str = Field(..., description="Executive summary")
    content_sections: List[Dict[str, Any]] = Field(..., description="Report content sections")
    metadata: Dict[str, Any] = Field(..., description="Report metadata")
    file_path: Optional[str] = Field(None, description="Generated file path")
    download_url: Optional[str] = Field(None, description="Download URL")
    generated_at: datetime = Field(..., description="Generation timestamp")
    expires_at: Optional[datetime] = Field(None, description="Expiration timestamp")


class ModelStatus(BaseModel):
    """NLP model status information"""
    model_name: str = Field(..., description="Model name")
    model_version: str = Field(..., description="Model version")
    status: str = Field(..., description="Model status")
    last_updated: datetime = Field(..., description="Last update timestamp")
    performance_metrics: Dict[str, float] = Field(..., description="Performance metrics")
    memory_usage_mb: float = Field(..., description="Memory usage in MB")
    inference_speed_ms: float = Field(..., description="Average inference speed in ms")
    accuracy: Optional[float] = Field(None, description="Model accuracy")
    supported_languages: List[str] = Field(..., description="Supported languages")


class ServiceHealth(BaseModel):
    """NLP Assistant service health"""
    status: str = Field(..., description="Service health status")
    timestamp: datetime = Field(..., description="Health check timestamp")
    models_loaded: int = Field(..., description="Number of models loaded")
    active_requests: int = Field(..., description="Number of active requests")
    queue_size: int = Field(..., description="Processing queue size")
    memory_usage_percent: float = Field(..., description="Memory usage percentage")
    cpu_usage_percent: float = Field(..., description="CPU usage percentage")
    last_error: Optional[str] = Field(None, description="Last error message")
    uptime_seconds: float = Field(..., description="Service uptime in seconds")


class AsyncJobStatus(BaseModel):
    """Async job status for long-running operations"""
    job_id: str = Field(..., description="Job identifier")
    job_type: str = Field(..., description="Type of job")
    status: str = Field(..., description="Job status")
    progress_percent: float = Field(..., description="Progress percentage (0-100)")
    started_at: datetime = Field(..., description="Job start time")
    estimated_completion: Optional[datetime] = Field(None, description="Estimated completion time")
    result_url: Optional[str] = Field(None, description="URL to fetch results")
    error_message: Optional[str] = Field(None, description="Error message if failed")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Job metadata")